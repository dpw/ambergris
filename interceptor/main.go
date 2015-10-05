package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"unicode"
)

type IPPort struct {
	// stringified form of the IP bytes, to be used as a map key
	ip   string
	Port int
}

func (ipport IPPort) IP() net.IP {
	return net.IP(([]byte)(ipport.ip))
}

func (ipport IPPort) TCPAddr() *net.TCPAddr {
	return &net.TCPAddr{IP: ipport.IP(), Port: ipport.Port}
}

type Instance struct {
	IPPort
}

func MakeInstance(ip net.IP, port int) Instance {
	return Instance{IPPort{string(ip), port}}
}

type ServiceKey struct {
	// Type of the service, e.g. "tcp" or "udp"
	Type string
	IPPort
}

func MakeServiceKey(typ string, ip net.IP, port int) ServiceKey {
	return ServiceKey{typ, IPPort{string(ip), port}}
}

type ServiceInfo struct {
	// Protocol, e.g. "http".  "" for simple tcp forwarding.
	Protocol  string
	Instances []Instance
}

type ServiceUpdate struct {
	ServiceKey
	*ServiceInfo
}

func parseService(s []string) (ServiceUpdate, error) {
	var res ServiceUpdate
	if len(s) < 1 {
		return res, fmt.Errorf("service specification should begin with port:ip-address")
	}

	addr, err := net.ResolveTCPAddr("tcp", s[0])
	if err != nil {
		return res, err
	}

	res.ServiceKey = MakeServiceKey("tcp", addr.IP, addr.Port)
	res.ServiceInfo = &ServiceInfo{}

	for _, inst := range s[1:] {
		addr, err := net.ResolveTCPAddr("tcp", inst)
		if err != nil {
			return res, err
		}

		res.Instances = append(res.Instances,
			MakeInstance(addr.IP, addr.Port))
	}

	return res, nil
}

func main() {
	var cf config

	// The bridge specified should be the one where packets sent
	// to service IP addresses go.  So even with weave, that's
	// typically 'docker0'.
	flag.StringVar(&cf.bridge, "bridge", "docker0", "bridge device")
	flag.StringVar(&cf.chain, "chain", "AMBERGRIS", "iptables chain name")
	flag.Parse()

	upd, err := parseService(flag.Args())
	if err != nil {
		fatal(err)
	}

	err = cf.setupChain()
	if err != nil {
		fatal(err)
	}

	errors := make(chan error, 1)
	updates := make(chan ServiceUpdate, 1)
	updater := cf.newUpdater(updates, errors)
	updates <- upd

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go readLines(updates, errors)

	select {
	case <-sigs:
	case err := <-errors:
		fatal(err)
	}

	updater.close()
	cf.deleteChain()
}

func readLines(updates chan<- ServiceUpdate, errors chan<- error) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		upd, err := parseService(strings.Split(scanner.Text(), " "))
		if err != nil {
			errors <- err
			return
		}

		updates <- upd
	}
}

type updater struct {
	config  *config
	updates <-chan ServiceUpdate
	errors  chan<- error

	lock     sync.Mutex
	closed   chan struct{}
	finished chan struct{}
	services map[ServiceKey]*service
}

func (config *config) newUpdater(updates <-chan ServiceUpdate, errors chan<- error) *updater {
	upd := &updater{
		config:   config,
		updates:  updates,
		errors:   errors,
		closed:   make(chan struct{}),
		finished: make(chan struct{}),
		services: make(map[ServiceKey]*service),
	}
	go upd.run()
	return upd
}

func (upd *updater) close() {
	upd.lock.Lock()
	defer upd.lock.Unlock()

	if upd.services != nil {
		close(upd.closed)
		<-upd.finished

		for _, svc := range upd.services {
			svc.close()
		}
	}
}

func (upd *updater) run() {
	for {
		select {
		case <-upd.closed:
			close(upd.finished)
			return

		case update := <-upd.updates:
			upd.doUpdate(update)
		}
	}
}

func (upd *updater) doUpdate(update ServiceUpdate) {
	svc := upd.services[update.ServiceKey]
	if svc == nil {
		if update.ServiceInfo == nil {
			return
		}

		svc, err := upd.config.newService(update, upd.errors)
		if err != nil {
			upd.errors <- err
			return
		}

		upd.services[update.ServiceKey] = svc
	} else if update.ServiceInfo != nil {
		svc.update(*update.ServiceInfo)
	} else {
		delete(upd.services, update.ServiceKey)
		svc.close()
	}
}

func fatal(a ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprint(a...))
	os.Exit(1)
}

type service struct {
	config      *config
	serviceAddr *net.TCPAddr
	instances   []Instance
	errors      chan<- error

	lock     sync.Mutex
	listener *net.TCPListener
	rule     []interface{}
	closed   chan struct{}
}

func (config *config) newService(upd ServiceUpdate, errors chan<- error) (*service, error) {
	bridgeIP, err := config.bridgeIP()
	if err != nil {
		return nil, err
	}

	svc := &service{
		config:      config,
		serviceAddr: upd.TCPAddr(),
		instances:   upd.Instances,
		errors:      errors,
		closed:      make(chan struct{}),
	}

	success := false
	defer func() {
		if !success {
			svc.close()
		}
	}()

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: bridgeIP})
	if err != nil {
		return nil, err
	}
	svc.listener = listener

	rule := []interface{}{
		"-p", "tcp",
		"-d", upd.IP(),
		"--dport", upd.Port,
		"-j", "DNAT",
		"--to-destination", listener.Addr(),
	}
	err = config.addRule(rule)
	if err != nil {
		return nil, err
	}
	svc.rule = rule

	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				select {
				case errors <- err:
				case <-svc.closed:
				}
				return
			}

			go svc.forward(conn)
		}
	}()

	success = true
	return svc, nil
}

func (svc *service) forward(local *net.TCPConn) {
	remote, err := net.DialTCP("tcp", nil, svc.pickInstance().TCPAddr())
	if remote == nil {
		fmt.Fprintf(os.Stderr, "remote dial failed: %v\n", err)
		return
	}

	ch := make(chan struct{})
	go func() {
		io.Copy(local, remote)
		// XXX report error
		remote.CloseRead()
		local.CloseWrite()
		close(ch)
	}()

	io.Copy(remote, local)
	// XXX report error
	local.CloseRead()
	remote.CloseWrite()

	<-ch
	local.Close()
	remote.Close()
}

func (svc *service) pickInstance() Instance {
	svc.lock.Lock()
	defer svc.lock.Unlock()
	return svc.instances[rand.Intn(len(svc.instances))]
}

func (svc *service) update(info ServiceInfo) {
	svc.lock.Lock()
	defer svc.lock.Unlock()
	svc.instances = info.Instances
}

func (svc *service) close() {
	svc.lock.Lock()
	defer svc.lock.Unlock()

	if svc.listener != nil {
		svc.listener.Close()
		close(svc.closed)
		svc.listener = nil
	}

	if svc.rule != nil {
		svc.config.deleteRule(svc.rule)
		svc.rule = nil
	}
}

type ipTablesError struct {
	cmd    string
	output string
}

func (err ipTablesError) Error() string {
	return fmt.Sprintf("'iptables %s' gave error: ", err.cmd, err.output)
}

func flatten(args []interface{}, onto []string) []string {
	for _, arg := range args {
		switch argt := arg.(type) {
		case []interface{}:
			onto = flatten(argt, onto)
		default:
			onto = append(onto, fmt.Sprint(arg))
		}
	}
	return onto
}

func doIPTables(args ...interface{}) error {
	flatArgs := flatten(args, nil)
	output, err := exec.Command("iptables", flatArgs...).CombinedOutput()
	switch errt := err.(type) {
	case nil:
	case *exec.ExitError:
		if !errt.Success() {
			// sanitize iptables output
			limit := 200
			sanOut := strings.Map(func(ch rune) rune {
				if limit == 0 {
					return -1
				}
				limit--

				if unicode.IsControl(ch) {
					ch = ' '
				}
				return ch
			}, string(output))
			return ipTablesError{
				cmd:    strings.Join(flatArgs, " "),
				output: sanOut,
			}
		}
	default:
		return err
	}

	return nil
}

type config struct {
	chain  string
	bridge string
}

func (cf *config) bridgeIP() (net.IP, error) {
	iface, err := net.InterfaceByName(cf.bridge)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, addr := range addrs {
		if cidr, ok := addr.(*net.IPNet); ok {
			if ip := cidr.IP.To4(); ip != nil {
				return ip, nil
			}
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on netdev %s", cf.bridge)
}

func (cf *config) chainRule() []interface{} {
	return []interface{}{"-i", cf.bridge, "-j", cf.chain}
}

func (cf *config) setupChain() error {
	err := cf.deleteChain()
	if err != nil {
		return err
	}

	err = doIPTables("-t", "nat", "-N", cf.chain)
	if err != nil {
		return err
	}

	return doIPTables("-t", "nat", "-A", "PREROUTING", cf.chainRule())
}

func (cf *config) deleteChain() error {
	// First, remove any rules in the chain
	err := doIPTables("-t", "nat", "-F", cf.chain)
	if err != nil {
		if _, ok := err.(ipTablesError); ok {
			// this probably means the chain doesn't exist
			return nil
		}
	}

	// Remove the rule that references our chain from PREROUTING,
	// if it's there.
	for {
		err := doIPTables("-t", "nat", "-D", "PREROUTING",
			cf.chainRule())
		if err != nil {
			if _, ok := err.(ipTablesError); !ok {
				return err
			}

			// a "no such rule" error
			break
		}
	}

	// Actually delete the chain at last
	return doIPTables("-t", "nat", "-X", cf.chain)
}

func (cf *config) addRule(args []interface{}) error {
	return cf.frobRule("-A", args)
}

func (cf *config) deleteRule(args []interface{}) error {
	return cf.frobRule("-D", args)
}

func (cf *config) frobRule(op string, args []interface{}) error {
	return doIPTables("-t", "nat", op, cf.chain, args)
}

package interceptor

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/bboreham/coatl/glisten"
	"github.com/dpw/ambergris/interceptor/model"
	"github.com/dpw/ambergris/interceptor/simplecontrol"
)

type config struct {
	chain  string
	bridge string
}

type Controller interface {
	Updates() <-chan model.ServiceUpdate
	Close()
}

func Main() error {
	var cf config

	// The bridge specified should be the one where packets sent
	// to service IP addresses go.  So even with weave, that's
	// typically 'docker0'.
	flag.StringVar(&cf.bridge, "bridge", "docker0", "bridge device")
	flag.StringVar(&cf.chain, "chain", "AMBERGRIS", "iptables chain name")
	flag.Parse()

	if flag.NArg() > 0 {
		return fmt.Errorf("excess command line arguments")
	}

	err := cf.setupChain()
	if err != nil {
		return err
	}
	defer cf.deleteChain()

	errors := make(chan error, 1)

	var controlServer Controller
	if false {
		controlServer, err = simplecontrol.NewServer(errors)
	} else {
		controlServer, err = glisten.NewListener(errors)
	}
	if err != nil {
		return err
	}
	defer controlServer.Close()

	updater := cf.newUpdater(controlServer.Updates(), errors)
	defer updater.close()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigs:
	case err := <-errors:
		return err
	}

	return nil
}

type updater struct {
	config  *config
	updates <-chan model.ServiceUpdate
	errors  chan<- error

	lock     sync.Mutex
	closed   chan struct{}
	finished chan struct{}
	services map[model.ServiceKey]*service
}

func (config *config) newUpdater(updates <-chan model.ServiceUpdate, errors chan<- error) *updater {
	upd := &updater{
		config:   config,
		updates:  updates,
		errors:   errors,
		closed:   make(chan struct{}),
		finished: make(chan struct{}),
		services: make(map[model.ServiceKey]*service),
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

func (upd *updater) doUpdate(update model.ServiceUpdate) {
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
}

type service struct {
	config      *config
	serviceAddr *net.TCPAddr
	instances   []model.Instance
	errors      chan<- error

	lock     sync.Mutex
	listener *net.TCPListener
	rule     []interface{}
	closed   chan struct{}
}

func (config *config) newService(upd model.ServiceUpdate, errors chan<- error) (*service, error) {
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
		// XXX report error
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

func (svc *service) pickInstance() model.Instance {
	svc.lock.Lock()
	defer svc.lock.Unlock()
	return svc.instances[rand.Intn(len(svc.instances))]
}

func (svc *service) update(info model.ServiceInfo) {
	// handle the "no instances" case nicely, by changing the rule to
	// REJECT.
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

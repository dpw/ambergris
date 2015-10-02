package main

import (
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unicode"
)

func main() {
	var cf config

	// The bridge specified should be the one where packets sent
	// to service IP addresses go.  So even with weave, that's
	// typically 'docker0'.
	flag.StringVar(&cf.bridge, "bridge", "docker0", "bridge device")
	flag.StringVar(&cf.chain, "chain", "AMBERGRIS", "iptables chain name")
	flag.Parse()

	if flag.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "usage: [options] service instances...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	err := cf.setupChain()
	if err != nil {
		fatal(err)
	}

	var insts []*net.TCPAddr
	for _, arg := range flag.Args()[1:] {
		insts = append(insts, resolve(arg))
	}

	fwd, err := cf.newForwarder(resolve(flag.Arg(0)), insts)
	if err != nil {
		fatal(err)
	}

	fatal(<-fwd.errors)
}

func resolve(addr string) *net.TCPAddr {
	res, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		fatal("cannot resolve ", addr, ":", err)
	}
	return res
}

func fatal(a ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprint(a...))
	os.Exit(1)
}

type forwarder struct {
	config        *config
	serviceAddr   *net.TCPAddr
	instanceAddrs []*net.TCPAddr
	errors        <-chan error

	lock     sync.Mutex
	listener *net.TCPListener
	closed   chan struct{}
}

func (config *config) newForwarder(serviceAddr *net.TCPAddr, instanceAddrs []*net.TCPAddr) (*forwarder, error) {
	bridgeIP, err := config.bridgeIP()
	if err != nil {
		return nil, err
	}

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: bridgeIP})
	if err != nil {
		return nil, err
	}

	localAddr := listener.Addr().(*net.TCPAddr)

	rule := []interface{}{
		"-p", "tcp",
		"-d", serviceAddr.IP,
		"--dport", serviceAddr.Port,
		"-j", "DNAT",
		"--to-destination", localAddr,
	}
	err = config.addRule(rule)
	if err != nil {
		return nil, err
	}

	defer func() {
		if rule != nil {
			config.deleteRule(rule)
		}
	}()

	errors := make(chan error)

	fwd := &forwarder{
		config:        config,
		serviceAddr:   serviceAddr,
		instanceAddrs: instanceAddrs,
		errors:        errors,

		listener: listener,
		closed:   make(chan struct{}),
	}

	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				select {
				case errors <- err:
				case <-fwd.closed:
				}
				return
			}

			go fwd.forward(conn)
		}
	}()

	rule = nil
	return fwd, nil
}

func (fwd *forwarder) forward(local *net.TCPConn) {
	addr := fwd.instanceAddrs[rand.Intn(len(fwd.instanceAddrs))]
	remote, err := net.DialTCP("tcp", nil, addr)
	if remote == nil {
		fmt.Fprintf(os.Stderr, "remote dial failed: %v\n", err)
		return
	}

	ch := make(chan struct{})
	go func() {
		io.Copy(local, remote)
		remote.CloseRead()
		local.CloseWrite()
		close(ch)
	}()

	io.Copy(remote, local)
	local.CloseRead()
	remote.CloseWrite()

	<-ch
	local.Close()
	remote.Close()
}

func (fwd *forwarder) close() {
	fwd.lock.Lock()
	defer fwd.lock.Unlock()

	if fwd.listener != nil {
		fwd.listener.Close()
		close(fwd.closed)
		fwd.listener = nil
	}
}

type ipTablesError struct {
	output string
}

func (err ipTablesError) Error() string {
	return fmt.Sprint("iptables error: ", err.output)
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
			return ipTablesError{sanOut}
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

func (cf *config) setupChain() error {
	refRule := []interface{}{"-i", cf.bridge, "-j", cf.chain}
	err := cf.deleteChain(refRule)
	if err != nil {
		return err
	}

	err = doIPTables("-t", "nat", "-N", cf.chain)
	if err != nil {
		return err
	}

	return doIPTables("-t", "nat", "-A", "PREROUTING", refRule)
}

func (cf *config) deleteChain(refRule []interface{}) error {
	// First, remove any rules in the chain
	err := doIPTables("-t", "nat", "-F", cf.chain)
	if err != nil {
		if _, ok := err.(ipTablesError); !ok {
			// this probably means the chain doesn't exist
			return nil
		}
	}

	// Remove the rule that references our chain from PREROUTING,
	// if it's there.
	for {
		err := doIPTables("-t", "nat", "-D", "PREROUTING", refRule)
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

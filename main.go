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
		fatal("usage: [options] service instances...")
		flag.PrintDefaults()
	}

	cf.setupChain()

	var insts []*net.TCPAddr
	for _, arg := range flag.Args()[1:] {
		insts = append(insts, resolve(arg))
	}

	svc := &service{
		config:        &cf,
		serviceAddr:   resolve(flag.Arg(0)),
		instanceAddrs: insts,
	}
	svc.startForwarding()
}

func resolve(addr string) *net.TCPAddr {
	res, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		fatal("cannot resolve ", addr, ":", err)
	}
	return res
}

type service struct {
	config        *config
	serviceAddr   *net.TCPAddr
	instanceAddrs []*net.TCPAddr
}

func (svc *service) startForwarding() {
	bridgeIP, err := svc.config.bridgeIP()
	if err != nil {
		fatal(err)
	}

	local, err := net.ListenTCP("tcp", &net.TCPAddr{IP: bridgeIP})
	if err != nil {
		fatal("cannot listen:", err)
	}

	localAddr := local.Addr().(*net.TCPAddr)
	err = svc.config.addRule("-p", "tcp", "-d", svc.serviceAddr.IP,
		"--dport", svc.serviceAddr.Port, "-j", "DNAT",
		"--to-destination", localAddr)
	if err != nil {
		fatal(err)
	}

	for {
		conn, err := local.AcceptTCP()
		if err != nil {
			fatal("accept failed:", err)
		}
		fmt.Println("Got connection")
		go svc.forward(conn)
	}
}

func (svc *service) forward(local *net.TCPConn) {
	addr := svc.instanceAddrs[rand.Intn(len(svc.instanceAddrs))]
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

func fatal(a ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprint(a...))
	os.Exit(1)
}

type ipTablesError struct {
	output string
}

func (err ipTablesError) Error() string {
	return fmt.Sprint("iptables error: ", err.output)
}

func doIPTables(args ...interface{}) error {
	sargs := make([]string, len(args))
	for i, arg := range args {
		sargs[i] = fmt.Sprint(arg)
	}

	output, err := exec.Command("iptables", sargs...).CombinedOutput()
	switch errt := err.(type) {
	case nil:
	case *exec.ExitError:
		if !errt.Success() {
			// sanitize iptables output
			limit := 200
			sanOut := strings.Map(func(ch rune) rune {
				if limit > 0 {
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
	// Remove any rules in our chain
	err := doIPTables("-t", "nat", "-F", cf.chain)
	if err != nil {
		if _, ok := err.(ipTablesError); !ok {
			return err
		}

		// Need to create our chain
		err = doIPTables("-t", "nat", "-N", cf.chain)
		if err != nil {
			return err
		}
	}

	// Is the chain already hooked into PREROUTING?
	// XXX what if it is hooked in for another bridge?
	err = doIPTables("-t", "nat", "-C", "PREROUTING", "-i", cf.bridge,
		"-j", cf.chain)
	if err == nil {
		// it's there already
		return nil
	}

	if _, ok := err.(ipTablesError); !ok {
		return err
	}

	return doIPTables("-t", "nat", "-A", "PREROUTING", "-i", cf.bridge,
		"-j", cf.chain)
}

func (cf *config) addRule(args ...interface{}) error {
	prefix := []interface{}{"-t", "nat", "-A", cf.chain}
	return doIPTables(append(prefix, args...)...)
}

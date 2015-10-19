package interceptor

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"

	"github.com/dpw/ambergris/interceptor/model"
)

type forwarding struct {
	*service
	rule     []interface{}
	listener *net.TCPListener
	stopCh   chan struct{}

	lock sync.Mutex
	*model.ServiceInfo
	shim shimFunc
}

type shimFunc func(inbound, outbound *net.TCPConn) error

func (svc *service) startForwarding(upd model.ServiceUpdate) (serviceState, error) {
	bridgeIP, err := svc.config.bridgeIP()
	if err != nil {
		return nil, err
	}

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: bridgeIP})
	if err != nil {
		return nil, err
	}

	success := false
	defer func() {
		if !success {
			listener.Close()
		}
	}()

	rule := []interface{}{
		"-p", "tcp",
		"-d", upd.IP(),
		"--dport", upd.Port,
		"-j", "DNAT",
		"--to-destination", listener.Addr(),
	}
	err = svc.config.addRule("nat", rule)
	if err != nil {
		return nil, err
	}

	fwd := &forwarding{
		service:     svc,
		rule:        rule,
		listener:    listener,
		stopCh:      make(chan struct{}),
		ServiceInfo: upd.ServiceInfo,
	}

	fwd.shim = fwd.chooseShim()
	go fwd.run()
	success = true
	return fwd, nil
}

func (fwd *forwarding) run() {
	for {
		conn, err := fwd.listener.AcceptTCP()
		if err != nil {
			select {
			case fwd.errors <- err:
			case <-fwd.stopCh:
			}
			return
		}

		go fwd.forward(conn)
	}
}

func (fwd *forwarding) stop() {
	fwd.listener.Close()
	close(fwd.stopCh)
	fwd.config.deleteRule("nat", fwd.rule)
}

func (fwd *forwarding) update(upd model.ServiceUpdate) (bool, error) {
	if len(upd.Instances) > 0 {
		fwd.lock.Lock()
		fwd.ServiceInfo = upd.ServiceInfo
		fwd.shim = fwd.chooseShim()
		fwd.lock.Unlock()
		return true, nil
	}

	return false, nil
}

func (fwd *forwarding) chooseShim() shimFunc {
	switch fwd.Protocol {
	case "":
		return fwd.tcpShim

	default:
		// XXX log warning
		return fwd.tcpShim
	}
}

func (fwd *forwarding) forward(inbound *net.TCPConn) {
	inst, shim := fwd.pickInstanceAndShim()

	outbound, err := net.DialTCP("tcp", nil, inst.TCPAddr())
	if err != nil {
		// XXX report error
		fmt.Fprintf(os.Stderr, "remote dial failed: %v\n", err)
		return
	}

	shim(inbound, outbound)
	// XXX handle errors from shim
}

func (fwd *forwarding) pickInstanceAndShim() (model.Instance, shimFunc) {
	fwd.lock.Lock()
	defer fwd.lock.Unlock()
	return fwd.Instances[rand.Intn(len(fwd.Instances))], fwd.shim
}

func (fwd *forwarding) tcpShim(inbound, outbound *net.TCPConn) error {
	ch := make(chan error, 1)
	go func() {
		var err error
		defer func() { ch <- err }()
		err = copyAndClose(inbound, outbound)
	}()

	err1 := copyAndClose(outbound, inbound)
	err2 := <-ch
	inbound.Close()
	outbound.Close()

	if err1 != nil {
		return err1
	} else {
		return err2
	}
}

func copyAndClose(dst, src *net.TCPConn) error {
	_, err1 := io.Copy(dst, src)
	err2 := src.CloseRead()
	err3 := dst.CloseWrite()
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	default:
		return err3
	}
}

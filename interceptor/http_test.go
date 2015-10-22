package interceptor

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type shimHarness struct {
	listener *net.TCPListener
}

func wrapShim(shim shimFunc, target *net.TCPAddr, check func(error)) *shimHarness {
	listener, err := net.ListenTCP("tcp", nil)
	check(err)

	go func() {
		for {
			inbound, err := listener.AcceptTCP()
			check(err)

			go func() {
				outbound, err := net.DialTCP("tcp", nil, target)
				check(err)
				check(shim(inbound, outbound))
			}()
		}
	}()

	return &shimHarness{listener}
}

func (h *shimHarness) addr() *net.TCPAddr {
	return h.listener.Addr().(*net.TCPAddr)
}

func (h *shimHarness) stop() error {
	return h.listener.Close()
}

func TestHttp(t *testing.T) {
	check := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}

	l, err := net.ListenTCP("tcp", nil)
	check(err)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randStr := func() string {
		return fmt.Sprint(r.Int63())
	}

	read := func(r io.ReadCloser) string {
		b, err := ioutil.ReadAll(r)
		check(err)
		check(r.Close())
		return string(b)
	}

	var expectOut, gotIn string

	mux := http.NewServeMux()
	mux.HandleFunc("/out", func(w http.ResponseWriter, req *http.Request) {
		w.Write(([]byte)(expectOut))
	})
	mux.HandleFunc("/in", func(w http.ResponseWriter, req *http.Request) {
		gotIn = read(req.Body)
	})
	mux.HandleFunc("/inout", func(w http.ResponseWriter, req *http.Request) {
		gotIn = read(req.Body)
		w.Write(([]byte)(expectOut))
	})
	go func() { http.Serve(l, mux) }()

	harness := wrapShim(httpShim, l.Addr().(*net.TCPAddr), check)
	url := fmt.Sprintf("http://localhost:%d/", harness.addr().Port)

	doGet := func() string {
		res, err := http.Get(url + "out")
		check(err)
		return read(res.Body)
	}

	doPost := func(s string) {
		_, err := http.Post(url+"in", "text/plain",
			bytes.NewBuffer(([]byte)(s)))
		check(err)
	}

	doPostInOut := func(s string) string {
		res, err := http.Post(url+"inout", "text/plain",
			bytes.NewBuffer(([]byte)(s)))
		check(err)
		return read(res.Body)
	}

	expectOut = randStr()
	require.Equal(t, doGet(), expectOut)

	expectIn := randStr()
	doPost(expectIn)
	require.Equal(t, gotIn, expectIn)

	expectIn = randStr()
	require.Equal(t, doPostInOut(expectIn), expectOut)
	require.Equal(t, gotIn, expectIn)

	expectOut = randStr()
	require.Equal(t, doGet(), expectOut)

	expectIn = randStr()
	doPost(expectIn)
	require.Equal(t, gotIn, expectIn)

	expectIn = randStr()
	require.Equal(t, doPostInOut(expectIn), expectOut)
	require.Equal(t, gotIn, expectIn)

	check(l.Close())
	check(harness.stop())
}

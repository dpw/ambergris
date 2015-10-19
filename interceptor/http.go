package interceptor

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

func httpShim(inbound, outbound *net.TCPConn) error {
	reqrd := bufio.NewReader(inbound)
	resprd := bufio.NewReader(outbound)
	defer inbound.Close()
	defer outbound.Close()

	for {
		// XXX timeout on no request
		req, err := http.ReadRequest(reqrd)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		req.Write(outbound)
		resp, err := http.ReadResponse(resprd, req)
		if err != nil {
			return err
		}

		resp.Write(inbound)
	}
}

package cert

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

func ExampleRandom() {
	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("Your IP Address: " + request.RemoteAddr))
	})

	// 1. create tls certification
	certs := Random(2048)
	listener, _ := tls.Listen("tcp", "127.0.0.1:2023", &tls.Config{Certificates: []tls.Certificate{certs}})

	// 2. start a http server
	fmt.Println("http served at https://127.0.0.1:2023")
	_ = http.Serve(listener, nil)
}

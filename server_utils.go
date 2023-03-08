package ipcert

import (
	"io"
	"log"
	"net"
	"net/http"
)

// open a http server on port 80 to serve verify files
// ! use mutex to prevent from conflict on port 80
func openVerifyServer(fileName, fileContent string, l net.Listener) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc(VerifyURLPrefix, func(w http.ResponseWriter, r *http.Request) {
		log.Println("&&&&&&&&&&&&&&&&", r)
		txt := r.URL.Path[len(VerifyURLPrefix):]
		if txt == fileName {
			w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			io.WriteString(w, fileContent)
		} else {
			w.WriteHeader(404)
		}
	})
	server := &http.Server{Handler: mux}
	go server.Serve(l)
	return server
}

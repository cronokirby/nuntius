package server

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func handler(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("Hello World!"))
}

func Run(port int) {
	r := mux.NewRouter()

	r.HandleFunc("/", handler).Methods("GET")

	srv := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf("localhost:%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

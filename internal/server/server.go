package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func handler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idBase64 := vars["id"]
	idBytes, err := base64.URLEncoding.DecodeString(idBase64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	fmt.Println(idBytes)

	var request PrekeyRequest
	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Println(request)

	w.WriteHeader(http.StatusAccepted)
}

func Run(port int) {
	r := mux.NewRouter()

	r.HandleFunc("/prekey/{id}", handler).Methods("POST")

	srv := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf("localhost:%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

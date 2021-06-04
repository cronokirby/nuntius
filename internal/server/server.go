package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
	"time"

	"github.com/cronokirby/nuntius/internal/crypto"
	"github.com/gorilla/mux"
)

type server struct {
	*sql.DB
}

const _DEFAULT_DATABASE_PATH = ".nuntius/server.db"

func newServer(database string) (*server, error) {
	if database == "" {
		usr, err := user.Current()
		if err != nil {
			return nil, err
		}
		database = path.Join(usr.HomeDir, _DEFAULT_DATABASE_PATH)
	}
	os.MkdirAll(path.Dir(database), os.ModePerm)
	db, err := sql.Open("sqlite", database)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS prekey (
		identity BLOB PRIMARY KEY NOT NULL,
		prekey BLOB NOT NULL,
		signature BLOB NOT NULL
	);

	CREATE TABLE IF NOT EXISTS onetime (
		id INTEGER PRIMARY KEY,
		identity BLOB NOT NULL,
		onetime BLOB NOT NULL
	);
	`)
	if err != nil {
		return nil, err
	}
	return &server{db}, nil
}

func (server *server) savePrekey(identity crypto.IdentityPub, prekey crypto.ExchangePub, signature []byte) error {
	_, err := server.Exec(`
	INSERT OR REPLACE INTO prekey (identity, prekey, signature) VALUES ($1, $2, $3);
	`, identity, prekey, signature)
	return err
}

func (server *server) countOnetimes(identity crypto.IdentityPub) (int, error) {
	var count int
	err := server.QueryRow(`
	SELECT COUNT(*) FROM onetime WHERE identity = $1;
	`, identity).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (server *server) saveBundle(identity crypto.IdentityPub, bundle crypto.BundlePub) error {
	tx, err := server.Begin()
	if err != nil {
		return err
	}
	for i := 0; i < bundle.Len(); i++ {
		_, err := tx.Exec(`
		INSERT INTO onetime (identity, onetime) VALUES ($1, $2);
		`, identity, bundle.Get(i))
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (server *server) getPrekey(pub crypto.IdentityPub) (crypto.ExchangePub, crypto.Signature, error) {
	var prekey crypto.ExchangePub
	var sig crypto.Signature
	err := server.QueryRow(`
	SELECT prekey, signature FROM prekey WHERE identity = $1;
	`, pub).Scan(&prekey, &sig)
	if err != nil {
		return nil, nil, err
	}
	return prekey, sig, nil
}

func (server *server) getOnetime(pub crypto.IdentityPub) (crypto.ExchangePub, error) {
	tx, err := server.Begin()
	if err != nil {
		return nil, err
	}
	var onetime crypto.ExchangePub
	err = tx.QueryRow(`
	SELECT onetime FROM onetime WHERE identity = $1 LIMIT 1;
	`, pub).Scan(&onetime)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	_, err = tx.Exec("DELETE FROM onetime WHERE onetime = $1;", onetime)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	tx.Commit()
	return onetime, nil
}

func (server *server) prekeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := crypto.IdentityPubFromBase64(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var request PrekeyRequest
	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	prekey, err := crypto.ExchangePubFromBytes(request.Prekey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !id.Verify(prekey, request.Sig) {
		http.Error(w, "bad signature", http.StatusBadRequest)
		return
	}

	err = server.savePrekey(id, request.Prekey, request.Sig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (server *server) onetimeCountHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := crypto.IdentityPubFromBase64(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	count, err := server.countOnetimes(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := CountOnetimeResponse{count}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

func (server *server) onetimeHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := crypto.IdentityPubFromBase64(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var request SendBundleRequest
	err = json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	bundle, err := crypto.BundleFromBytes(request.Bundle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !id.VerifyBundle(bundle, request.Sig) {
		http.Error(w, "bad signature", http.StatusBadRequest)
		return
	}

	err = server.saveBundle(id, bundle)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (server *server) sessionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := crypto.IdentityPubFromBase64(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	prekey, sig, err := server.getPrekey(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	onetime, err := server.getOnetime(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := SessionResponse{
		prekey,
		sig,
		onetime,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(response)
}

func Run(database string, port int) {
	server, err := newServer(database)
	if err != nil {
		log.Fatal(err)
	}
	r := mux.NewRouter()

	r.HandleFunc("/prekey/{id}", server.prekeyHandler).Methods("POST")
	r.HandleFunc("/onetime/{id}", server.onetimeHandler).Methods("POST")
	r.HandleFunc("/onetime/count/{id}", server.onetimeCountHandler).Methods("GET")
	r.HandleFunc("/session/{id}", server.sessionHandler).Methods("POST")

	srv := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf("localhost:%d", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

package server

import (
	"log"
	"net/http"
	"sync"

	"github.com/cronokirby/nuntius/internal/crypto"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

func forwardMessages(messages <-chan Message, conn *websocket.Conn) {
	for {
		message, open := <-messages
		if !open {
			return
		}
		err := conn.WriteJSON(message)
		if err != nil {
			log.Default().Println(err)
		}
	}
}

type router struct {
	channels     map[string]chan Message
	channelsLock sync.RWMutex
	upgrader     websocket.Upgrader
}

func newRouter() *router {
	var router router
	router.channels = make(map[string]chan Message)
	return &router
}

func (router *router) setChannel(id crypto.IdentityPub, ch chan Message) {
	router.channelsLock.Lock()
	defer router.channelsLock.Unlock()
	router.channels[string(id)] = ch
}

func (router *router) getChannel(id crypto.IdentityPub) (chan Message, bool) {
	router.channelsLock.RLock()
	defer router.channelsLock.RUnlock()
	ch, present := router.channels[string(id)]
	return ch, present
}

func (router *router) removeChannel(id crypto.IdentityPub) {
	router.channelsLock.Lock()
	defer router.channelsLock.Unlock()
	delete(router.channels, string(id))
}

func (router *router) listen(id crypto.IdentityPub, conn *websocket.Conn) error {
	ch := make(chan Message)
	router.setChannel(id, ch)
	defer router.removeChannel(id)
	go forwardMessages(ch, conn)
	for {
		var message Message
		err := conn.ReadJSON(&message)
		if err != nil {
			log.Default().Println(err)
			continue
		}
		message.From = id
		if len(message.To) != crypto.IdentityPubSize {
			log.Default().Printf("incorrect recipient identity len: %d\n", len(message.To))
			continue
		}
		idTo := crypto.IdentityPub(message.To)
		toChan, present := router.getChannel(idTo)
		if !present {
			log.Default().Printf("recipient %s is not connected\n", idTo)
			continue
		}
		toChan <- message
	}
}

func (router *router) rtcHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := crypto.IdentityPubFromBase64(vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	conn, err := router.upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = router.listen(id, conn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

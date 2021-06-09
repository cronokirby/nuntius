package server

import (
	"log"
	"sync"

	"github.com/cronokirby/nuntius/internal/crypto"
	"github.com/gorilla/websocket"
)

func forwardMessages(messages <-chan Message, conn websocket.Conn) {
	message, closed := <-messages
	if closed {
		return
	}
	err := conn.WriteJSON(message)
	if err != nil {
		log.Default().Println(err)
	}
}

type router struct {
	channels     map[string]chan Message
	channelsLock sync.RWMutex
	upgrader     websocket.Upgrader
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

func (router *router) listen(id crypto.IdentityPub, conn websocket.Conn) error {
	ch := make(chan Message)
	router.setChannel(id, ch)
	defer router.removeChannel(id)
	go forwardMessages(ch, conn)
	for {
		var message Message
		err := conn.ReadJSON(message)
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

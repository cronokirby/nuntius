package server

import (
	"encoding/json"
	"fmt"
)

type PrekeyRequest struct {
	Prekey []byte `json:"prekey"`
	Sig    []byte `json:"sig"`
}

type CountOnetimeResponse struct {
	Count int `json:"count"`
}

type SendBundleRequest struct {
	Bundle []byte `json:"bundle"`
	Sig    []byte `json:"sig"`
}

type SessionResponse struct {
	Prekey  []byte `json:"prekey"`
	Sig     []byte `json:"sig"`
	OneTime []byte `json:"onetime,omitempty"`
}

type Message struct {
	From    []byte  `json:"from,omitempty"`
	To      []byte  `json:"to"`
	Payload Payload `json:"payload"`
}

type Payload struct {
	Variant interface{} `json:"variant"`
}

func (payload Payload) MarshalJSON() ([]byte, error) {
	return json.Marshal(payload.Variant)
}

type MessagePayload struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
}

func (payload *MessagePayload) MarshalJSON() ([]byte, error) {
	type Alias MessagePayload
	return json.Marshal(&struct {
		Type string `json:"type"`
		*Alias
	}{
		Type:  "message",
		Alias: (*Alias)(payload),
	})
}

type StartExchangePayload struct {
	Prekey  []byte `json:"prekey"`
	Sig     []byte `json:"sig"`
	OneTime []byte `json:"onetime,omitempty"`
}

func (payload *StartExchangePayload) MarshalJSON() ([]byte, error) {
	type Alias StartExchangePayload
	return json.Marshal(&struct {
		Type string `json:"type"`
		*Alias
	}{
		Type:  "start_exchange",
		Alias: (*Alias)(payload),
	})
}

type EndExchangePayload struct {
	Prekey    []byte `json:"prekey"`
	OneTime   []byte `json:"onetime,omitempty"`
	Ephemeral []byte `json:"ephemeral"`
}

func (payload *EndExchangePayload) MarshalJSON() ([]byte, error) {
	type Alias EndExchangePayload
	return json.Marshal(&struct {
		Type string `json:"type"`
		*Alias
	}{
		Type:  "end_exchange",
		Alias: (*Alias)(payload),
	})
}

func (payload *Payload) UnmarshalJSON(data []byte) error {
	var typ struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &typ); err != nil {
		return err
	}
	switch typ.Type {
	case "message":
		payload.Variant = new(MessagePayload)
	case "start_exchange":
		payload.Variant = new(StartExchangePayload)
	case "end_exchange":
		payload.Variant = new(EndExchangePayload)
	default:
		return fmt.Errorf("unknown variant: %s", typ.Type)
	}
	return json.Unmarshal(data, payload.Variant)
}

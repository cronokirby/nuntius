package server

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
	From    []byte `json:"from"`
	To      []byte `json:"to"`
	Payload []byte `json:"payload"`
}

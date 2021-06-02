package server

type PrekeyRequest struct {
	Prekey []byte `json:"prekey"`
	Sig    []byte `json:"sig"`
}

type CountOnetimeResponse struct {
	Count int `json:"count"`
}

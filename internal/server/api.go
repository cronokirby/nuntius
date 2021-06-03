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

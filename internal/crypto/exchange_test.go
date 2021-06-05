package crypto

import (
	"bytes"
	"testing"
)

func TestExchangeSymmetry(t *testing.T) {
	pubA, privA, err := GenerateIdentity()
	if err != nil {
		t.Error(err)
	}
	ephemeralPub, ephemeralPriv, err := GenerateExchange()
	if err != nil {
		t.Error(err)
	}
	pubB, privB, err := GenerateIdentity()
	if err != nil {
		t.Error(err)
	}
	prekeyPub, prekeyPriv, err := GenerateExchange()
	if err != nil {
		t.Error(err)
	}
	onetimePub, onetimePriv, err := GenerateExchange()
	if err != nil {
		t.Error(err)
	}

	exchangeForward, err := ForwardExchange(&ForwardExchangeParams{
		privA,
		ephemeralPriv,
		pubB,
		prekeyPub,
		onetimePub,
	})
	if err != nil {
		t.Error(err)
	}
	exchangeBackward, err := BackwardExchange(&BackwardExchangeParams{
		pubA,
		ephemeralPub,
		privB,
		prekeyPriv,
		onetimePriv,
	})
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(exchangeForward, exchangeBackward) {
		t.Error("exchange wasn't symmetric:", exchangeForward, exchangeBackward)
	}

	exchangeForward, err = ForwardExchange(&ForwardExchangeParams{
		privA,
		ephemeralPriv,
		pubB,
		prekeyPub,
		nil,
	})
	if err != nil {
		t.Error(err)
	}
	exchangeBackward, err = BackwardExchange(&BackwardExchangeParams{
		pubA,
		ephemeralPub,
		privB,
		prekeyPriv,
		nil,
	})
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(exchangeForward, exchangeBackward) {
		t.Error("exchange wasn't symmetric:", exchangeForward, exchangeBackward)
	}
}

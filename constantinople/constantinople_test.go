package constantinople

import (
	"testing"

	"crypto/rand"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

const (
	deg    = 16
	secret = 2
)

var (
	coin = []byte{0x05, 0xf1}
)

func TestProof(t *testing.T) {
	index := make([]big.Int, deg)
	for i := range index {
		v, err := rand.Int(rand.Reader, bn256.Order)
		if err != nil {
			t.Error(err)
		}
		index[i] = *v
	}
	pi, shs, err := GenerateData(rand.Reader, big.NewInt(secret), index, deg)
	if err != nil {
		t.Error(err)
	}
	prs := make([]Proof, deg)
	for i := range index {
		pr, err := GenerateProof(rand.Reader, &shs[i], coin)
		if err != nil {
			t.Error(err)
		}
		prs[i] = *pr
		err = VerifyProof(pi, i, coin, &prs[i])
		if err != nil {
			t.Error(err)
		}
	}
	Reconstruct(prs)
}

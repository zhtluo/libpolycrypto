package evss

import (
	"testing"

	"crypto/rand"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"math/big"
)

const (
	deg = 16
)

func TestVerifyShare(t *testing.T) {
	constant, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		t.Error(err.Error())
	}
	s, err := GenerateSecret(rand.Reader, constant, deg)
	if err != nil {
		t.Error(err.Error())
	}
	pi, err := GeneratePublicInfo(rand.Reader, s)
	if err != nil {
		t.Error(err.Error())
	}
	for i := 0; i < deg; i++ {
		index := big.NewInt(int64(i))
		sh, err := GenerateShare(pi, s, index)
		if err != nil {
			t.Error(err.Error())
		}
		flag := VerifyShare(pi, sh)
		if !flag {
			t.Error("VerifyShare failed. Expected: true")
		}
		r, _ := rand.Int(rand.Reader, bn256.Order)
		sh.Result = *r
		flag = VerifyShare(pi, sh)
		if flag {
			t.Error("VerifyShare failed. Expected: false")
		}
	}
}

func TestReconstructSecret(t *testing.T) {
	constant, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		t.Error(err.Error())
	}
	s, err := GenerateSecret(rand.Reader, constant, deg)
	if err != nil {
		t.Error(err.Error())
	}
	pi, err := GeneratePublicInfo(rand.Reader, s)
	if err != nil {
		t.Error(err.Error())
	}
	shs := make([]Share, deg)
	for i := 0; i < deg; i++ {
		index := big.NewInt(int64(i + 1))
		sh, err := GenerateShare(pi, s, index)
		if err != nil {
			t.Error(err.Error())
		}
		shs[i] = *sh
	}
	reconstructed := ReconstructSecret(shs)
	if constant.Cmp(reconstructed) != 0 {
		t.Errorf("ReconstructSecret failed. Expected: %s, Got: %s", constant.String(), reconstructed.String())
	}
}

func TestMarshal(t *testing.T) {
	constant, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		t.Error(err.Error())
	}
	s, err := GenerateSecret(rand.Reader, constant, deg)
	if err != nil {
		t.Error(err.Error())
	}
	pi, err := GeneratePublicInfo(rand.Reader, s)
	if err != nil {
		t.Error(err.Error())
	}
	b, err := pi.Marshal()
	if err != nil {
		t.Error(err.Error())
	}
	var rPi PublicInfo
	err = rPi.Unmarshal(b)
	if err != nil {
		t.Error(err.Error())
	}
	for i := 0; i < deg; i++ {
		index := big.NewInt(int64(i))
		sh, err := GenerateShare(pi, s, index)
		if err != nil {
			t.Error(err.Error())
		}
		b, err = sh.Marshal()
		if err != nil {
			t.Error(err.Error())
		}
		var rSh Share
		err = rSh.Unmarshal(b)
		if err != nil {
			t.Error(err.Error())
		}
		flag := VerifyShare(&rPi, &rSh)
		if !flag {
			t.Error("VerifyShare failed. Expected: true")
		}
		r, _ := rand.Int(rand.Reader, bn256.Order)
		sh.Result = *r
		flag = VerifyShare(&rPi, sh)
		if flag {
			t.Error("VerifyShare failed. Expected: false")
		}
	}
}

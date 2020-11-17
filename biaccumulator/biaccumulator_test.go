package biaccumulator

import (
	"crypto/rand"
	"testing"

	"math/big"
)

func TestExpand(t *testing.T) {
	cred := make([]big.Int, 2)
	cred[0].SetInt64(2)
	cred[1].SetInt64(3)
	poly := Expand(cred)
	// x^2 - 5x + 6
	if len(poly) != 3 || poly[0].String() != "6" || poly[1].String() != "-5" || poly[2].String() != "1" {
		t.Error("Wrong expansion, got:", poly)
	}
}

func TestWitness(t *testing.T) {
	cred := make([]big.Int, 2)
	cred[0].SetInt64(2)
	cred[1].SetInt64(3)
	poly := Expand(cred)
	pi := new(PublicInfo)
	err := pi.Setup(rand.Reader, 3)
	if err != nil {
		t.Error(err)
	}
	g2, err := Evaluate(pi, poly)
	if err != nil {
		t.Error(err)
	}
	g1, err := CreateWitness(pi, poly, &cred[0])
	if err != nil {
		t.Error(err)
	}
	if Verify(pi, g2, g1, &cred[0]) == false {
		t.Error("Verify failed.")
	}
	g1, err = CreateWitness(pi, poly, big.NewInt(5))
	if err == nil {
		t.Error("Invalid credential accepted")
	}
}

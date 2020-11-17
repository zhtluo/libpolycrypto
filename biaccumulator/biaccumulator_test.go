package biaccumulator

import (
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

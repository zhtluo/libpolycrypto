package biaccumulator

import (
	"errors"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/zhtluo/libpolycrypto/polycommit"
)

type PublicInfo = polycommit.Pk

func Expand(cred []big.Int) (poly []big.Int) {
	poly = make([]big.Int, len(cred)+1)
	poly[0].SetInt64(1)
	// Polynomial expansion. Change to FFT if necessary.
	for i := range cred {
		for j := i + 1; j >= 1; j-- {
			poly[j].Sub(&poly[j-1], new(big.Int).Mul(&poly[j], &cred[i]))
		}
		poly[0].Neg(poly[0].Mul(&poly[0], &cred[i]))
	}
	return
}

func Evaluate(pi *PublicInfo, poly []big.Int) (*bn256.G2, error) {
	return pi.Commit(poly)
}

func CreateWitness(pi *PublicInfo, poly []big.Int, d *big.Int) (*bn256.G1, error) {
	res, g1, err := pi.CreateWitness(poly, d)
	if err != nil {
		return nil, err
	}
	if res.Cmp(big.NewInt(0)) != 0 {
		return nil, errors.New("Polynomial does not contain credential.")
	}
	return g1, nil
}

func Verify(pi *PublicInfo, g2 *bn256.G2, g1 *bn256.G1, d *big.Int) bool {
	return pi.VerifyEval(g2, d, big.NewInt(0), g1)
}

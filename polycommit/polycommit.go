// Package polycommit implements polycommit_dl found in section 3.2,
// A. Kate, et al.
// Constant-Size Commitments to Polynomials and Their Applications.

package polycommit

import (
	"io"
	"errors"
	"bytes"
	"math/big"
	"crypto/rand"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

// Struct PK implements a public key for polycommit to function on.
// It is the basic structure for all operations.
type PK struct {
	G1P []bn256.G1
	G2P []bn256.G2
}

func (pk *PK) checkPoly(poly []big.Int) error {
	if (len(poly) < 1) {
		return errors.New("Polynomial is empty")
	}
	if (pk.Degree() < len(poly)) {
		return errors.New("Public key has a degree less than the polynomial")
	}
	return nil
}

// Create a new public key for commitment,
// with the randomness generated in reader r and degree t.
func (pk *PK) Setup(r io.Reader, t int) error {
	pk.G1P = make([]bn256.G1, t)
	pk.G2P = make([]bn256.G2, t)
	alpha, err := rand.Int(r, bn256.Order)
	if err != nil {
		return err
	}
	alpha = big.NewInt(1)
	am := big.NewInt(1)
	pk.G1P[0].ScalarBaseMult(big.NewInt(1))
	pk.G2P[0].ScalarBaseMult(big.NewInt(1))
	for i := 1; i < t; i++ {
		am.Mul(am, alpha)
		pk.G1P[i].ScalarMult(&pk.G1P[0], am)
		pk.G2P[i].ScalarMult(&pk.G2P[0], am)
	}
	return nil
}

// Return the degree of the current public key.
func (pk *PK) Degree() int {
	return len(pk.G1P)
}

// Generate the commitment of the polynomial poly.
func (pk *PK) Commit(poly []big.Int) (*bn256.G2, error) {
	err := pk.checkPoly(poly)
	if err != nil {
		return nil, err
	}
	ret := new(bn256.G2)
	term := new(bn256.G2)
	for i, _ := range(poly) {
		if poly[i].Sign() >= 0 {
			term.ScalarMult(&pk.G2P[i], &poly[i])
		} else {
			term.Neg(term.ScalarMult(&pk.G2P[i], new(big.Int).Neg(&poly[i])))
		}
		ret.Add(ret, term)
	}
	return ret, nil
}

// Verify that the commitment g2 is consistent with the polynomial poly.
func (pk *PK) VerifyPoly(poly []big.Int, g2 *bn256.G2) bool {
	g2c, err := pk.Commit(poly)
	if (err != nil) {
		return false
	}
	return bytes.Equal(g2.Marshal(), g2c.Marshal())
}

// Create a witness g1 to the evaluation of the polynomial poly at i.
func (pk *PK) CreateWitness(poly []big.Int, i *big.Int) (res *big.Int, g1 *bn256.G1, err error) {
	err = pk.checkPoly(poly)
	if err != nil {
		return nil, nil, err
	}
	// poly(x) - poly(i) always divides (x - i) since the latter is a root of the former.
	// With that infomation we can jump into the division.
	quotient := make([]big.Int, len(poly) - 1)
	if len(quotient) > 0 {
		// q_(n - 1) = p_n
		quotient[len(quotient) - 1] = poly[len(quotient)]
		for j := len(quotient) - 2; j >= 0; j-- {
			// q_j = p_(j + 1) + q_(j + 1) * i
			quotient[j].Add(&poly[j + 1], quotient[j].Mul(&quotient[j + 1], i))
		}
	}
	// Utilize the remainder since we know it divides.
	res = new(big.Int)
	res.Add(&poly[0], res.Mul(&quotient[0], i))
	g1 = new(bn256.G1)
	term_g1 := new(bn256.G1)
	for j, _ := range(quotient) {
		if quotient[j].Sign() >= 0 {
			term_g1.ScalarMult(&pk.G1P[j], &quotient[j])
		} else {
			term_g1.Neg(term_g1.ScalarMult(&pk.G1P[j], new(big.Int).Neg(&quotient[j])))
		}
		g1.Add(g1, term_g1)
	}
	return res, g1, nil
}

// Verify the evaluation of the polynomial with the commitment g2 and the witness g1.
func (pk *PK) VerifyEval(g2 *bn256.G2, i *big.Int, res *big.Int, g1 *bn256.G1) bool {
	g_i := new(bn256.G2)
	g_i.ScalarBaseMult(i)
	p := new(bn256.G2)
	p.Add(&pk.G2P[1], p.Neg(g_i))
	rhs := bn256.Pair(&pk.G1P[0], &pk.G2P[0])
	rhs.Add(bn256.Pair(g1, p), rhs.ScalarMult(rhs, res))
	lhs := bn256.Pair(&pk.G1P[0], g2)
	return bytes.Equal(lhs.Marshal(), rhs.Marshal())
}

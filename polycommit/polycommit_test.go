package polycommit

import (
	"testing"

	"bytes"
	"crypto/rand"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"io"
	"math/big"
)

const (
	deg = 256
)

func generatePoly(r io.Reader) []big.Int {
	poly := make([]big.Int, deg)
	for i, _ := range poly {
		var p *big.Int
		p, _ = rand.Int(r, bn256.Order)
		poly[i] = *p
	}
	return poly
}

func TestCommit(t *testing.T) {
	var pk Pk
	pk.Setup(rand.Reader, deg)
	poly := generatePoly(rand.Reader)
	g2, err := pk.Commit(poly)
	if err != nil {
		t.Error(err.Error())
	}
	flag := pk.VerifyPoly(poly, g2)
	if flag != true {
		t.Error("VerifyPoly failed, expected: true.")
	}
	poly = generatePoly(rand.Reader)
	flag = pk.VerifyPoly(poly, g2)
	if flag != false {
		t.Error("VerifyPoly failed, expected: false.")
	}
}

func TestWitness(t *testing.T) {
	var pk Pk
	pk.Setup(rand.Reader, deg)
	// x^3 - 2x^2 + 7x - 5
	poly := []big.Int{*big.NewInt(-5), *big.NewInt(7), *big.NewInt(-2), *big.NewInt(1)}
	g2, err := pk.Commit(poly)
	if err != nil {
		t.Error(err.Error())
	}
	i := big.NewInt(3)
	res, g1, err := pk.CreateWitness(poly, i)
	if err != nil {
		t.Error(err.Error())
	}
	// 3^3 - 2*3^2 + 7*3 - 5 = 25
	if res.Cmp(big.NewInt(25)) != 0 {
		t.Error("CreateWitness failed. Wrong evaluation result.")
	}
	if pk.VerifyEval(g2, i, res, g1) != true {
		t.Error("VerifyEval failed, expected: true.")
	}
	if pk.VerifyEval(g2, i, big.NewInt(24), g1) != false {
		t.Error("VerifyEval failed, expected: false.")
	}
	// random polynomial
	poly = generatePoly(rand.Reader)
	g2, err = pk.Commit(poly)
	if err != nil {
		t.Error(err.Error())
	}
	i, _ = rand.Int(rand.Reader, bn256.Order)
	res, g1, err = pk.CreateWitness(poly, i)
	if err != nil {
		t.Error(err.Error())
	}
	if pk.VerifyEval(g2, i, res, g1) != true {
		t.Error("VerifyEval failed, expected: true.")
	}
	res, _ = rand.Int(rand.Reader, bn256.Order)
	if pk.VerifyEval(g2, i, res, g1) != false {
		t.Error("VerifyEval failed, expected: false.")
	}
}

func TestMarshal(t *testing.T) {
	var pk, rPk Pk
	pk.Setup(rand.Reader, deg)
	b, err := pk.Marshal()
	if err != nil {
		t.Error(err)
	}
	err = rPk.Unmarshal(b)
	if err != nil {
		t.Error(err)
	}
	if len(pk.G1P) != len(rPk.G1P) || len(pk.G2P) != len(rPk.G2P) {
		t.Error("Marshal does not generate equal result.")
	}
	for i, _ := range pk.G1P {
		if !bytes.Equal(pk.G1P[i].Marshal(), rPk.G1P[i].Marshal()) {
			t.Error("Marshal does not generate equal result.")
		}
		if !bytes.Equal(pk.G2P[i].Marshal(), rPk.G2P[i].Marshal()) {
			t.Error("Marshal does not generate equal result.")
		}
	}
}

func BenchmarkCommit(b *testing.B) {
	var pk Pk
	pk.Setup(rand.Reader, deg)
	poly := generatePoly(rand.Reader)
	b.ResetTimer()
	for t := 0; t < b.N; t++ {
		pk.Commit(poly)
	}
}

func BenchmarkVerifyPoly(b *testing.B) {
	var pk Pk
	pk.Setup(rand.Reader, deg)
	poly := generatePoly(rand.Reader)
	g2, _ := pk.Commit(poly)
	b.ResetTimer()
	for t := 0; t < b.N; t++ {
		pk.VerifyPoly(poly, g2)
	}
}

func BenchmarkCreateWitness(b *testing.B) {
	var pk Pk
	pk.Setup(rand.Reader, deg)
	poly := generatePoly(rand.Reader)
	i, _ := rand.Int(rand.Reader, bn256.Order)
	b.ResetTimer()
	for t := 0; t < b.N; t++ {
		pk.CreateWitness(poly, i)
	}
}

func BenchmarkVerifyEval(b *testing.B) {
	var pk Pk
	pk.Setup(rand.Reader, deg)
	poly := generatePoly(rand.Reader)
	g2, _ := pk.Commit(poly)
	i, _ := rand.Int(rand.Reader, bn256.Order)
	res, g1, _ := pk.CreateWitness(poly, i)
	b.ResetTimer()
	for t := 0; t < b.N; t++ {
		pk.VerifyEval(g2, i, res, g1)
	}
}

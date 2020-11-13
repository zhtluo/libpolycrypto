package constantinople

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

type PublicInfo struct {
	V []bn256.G1
}

type Share struct {
	S     big.Int
	Index big.Int
}

// Proof on DLEQ with random r and
// Pi = r + s[i] * hash(Gb, Gbi, Gr, Gbr, V).
type Proof struct {
	Gbi bn256.G1
	Gr  bn256.G1
	Gbr bn256.G1
	Pi  big.Int
}

func GenerateData(r io.Reader, secret *big.Int, index []big.Int, degree int) (*PublicInfo, []Share, error) {
	poly := make([]big.Int, degree)
	poly[0] = *secret
	for i := 1; i < degree; i++ {
		v, err := rand.Int(r, bn256.Order)
		if err != nil {
			return nil, nil, err
		}
		poly[i] = *v
	}
	pi := new(PublicInfo)
	pi.V = make([]bn256.G1, len(index))
	sh := make([]Share, len(index))
	for i := 0; i < len(index); i++ {
		sh[i].Index = index[i]
		term := new(big.Int)
		power := big.NewInt(1)
		for j := 0; j < degree; j++ {
			sh[i].S.Add(&sh[i].S, term.Mul(&poly[j], power))
			sh[i].S.Mod(&sh[i].S, bn256.Order)
			power.Mod(power.Mul(power, &sh[i].Index), bn256.Order)
		}
		pi.V[i].ScalarBaseMult(&sh[i].S)
	}
	return pi, sh, nil
}

func generateHashFromArray(g []*bn256.G1) *big.Int {
	bytes := make([]byte, 0)
	for i := range g {
		bytes = append(bytes, g[i].Marshal()...)
	}
	hash := sha256.Sum256(bytes)
	return new(big.Int).SetBytes(hash[:])
}

func generateCoin(coin []byte) *bn256.G1 {
	hash := sha256.Sum256(coin)
	return new(bn256.G1).ScalarBaseMult(new(big.Int).SetBytes(hash[:]))
}

func GenerateProof(r io.Reader, sh *Share, coin []byte) (*Proof, error) {
	pr := new(Proof)
	gb := generateCoin(coin)
	rVal, err := rand.Int(r, bn256.Order)
	if err != nil {
		return nil, err
	}
	pr.Gbi.ScalarMult(gb, &sh.S)
	pr.Gr.ScalarBaseMult(rVal)
	pr.Gbr.ScalarMult(gb, rVal)
	pr.Pi.Mod(pr.Pi.Add(pr.Pi.Mul(generateHashFromArray(
		[]*bn256.G1{gb, &pr.Gbi, &pr.Gr, &pr.Gbr, new(bn256.G1).ScalarBaseMult(&sh.S)}),
		&sh.S), rVal), bn256.Order)
	return pr, nil
}

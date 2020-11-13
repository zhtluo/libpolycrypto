package constantinople

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
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
	Gbi   bn256.G1
	Gr    bn256.G1
	Gbr   bn256.G1
	Pi    big.Int
	Index big.Int
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
	pr.Index.Set(&sh.Index)
	pr.Gbi.ScalarMult(gb, &sh.S)
	pr.Gr.ScalarBaseMult(rVal)
	pr.Gbr.ScalarMult(gb, rVal)
	pr.Pi.Mod(pr.Pi.Add(pr.Pi.Mul(generateHashFromArray(
		[]*bn256.G1{gb, &pr.Gbi, &pr.Gr, &pr.Gbr, new(bn256.G1).ScalarBaseMult(&sh.S)}),
		&sh.S), rVal), bn256.Order)
	return pr, nil
}

func VerifyProof(pi *PublicInfo, id int, coin []byte, pr *Proof) error {
	gb := generateCoin(coin)
	hash := generateHashFromArray(
		[]*bn256.G1{gb, &pr.Gbi, &pr.Gr, &pr.Gbr, &pi.V[id]})
	hash.Mod(hash, bn256.Order)

	GPi := new(bn256.G1).ScalarBaseMult(&pr.Pi)
	GbPi := new(bn256.G1).ScalarMult(gb, &pr.Pi)

	Vx := new(bn256.G1).ScalarMult(&pi.V[id], hash)
	GRhs := new(bn256.G1).Add(&pr.Gr, Vx)
	Gbix := new(bn256.G1).ScalarMult(&pr.Gbi, hash)
	GbRhs := new(bn256.G1).Add(&pr.Gbr, Gbix)

	if !bytes.Equal(GPi.Marshal(), GRhs.Marshal()) ||
		!bytes.Equal(GbPi.Marshal(), GbRhs.Marshal()) {
		return errors.New("DLEQ verification failed.")
	}
	return nil
}

func interpolate(prs []Proof) *bn256.G1 {
	inverse := make([]big.Int, len(prs))
	for i := range inverse {
		inverse[i].ModInverse(&prs[i].Index, bn256.Order)
	}
	val := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	// Order + 1
	orders1 := new(big.Int).Add(bn256.Order, big.NewInt(1))
	for i := range prs {
		partial := big.NewInt(1)
		for j := range prs {
			if i != j {
				// p = p * (1 - x_i * x_j^-1)
				term := new(big.Int).Mul(&prs[i].Index, &inverse[j])
				term.Mod(term, bn256.Order)
				partial.Mul(partial, new(big.Int).Sub(orders1, term))
				partial.Mod(partial, bn256.Order)
			}
		}
		partial.ModInverse(partial, bn256.Order)
		val.Add(val, new(bn256.G1).ScalarMult(&prs[i].Gbi, partial))
	}
	return val
}

func Reconstruct(prs []Proof) *big.Int {
	hash := sha256.Sum256(interpolate(prs).Marshal())
	return new(big.Int).SetBytes(hash[:])
}

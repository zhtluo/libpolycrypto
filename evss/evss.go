// Package evss implements eVSS found in section 4.1,
// A. Kate, et al.
// Constant-Size Commitments to Polynomials and Their Applications.

package evss

import (
	"crypto/rand"
	"io"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/zhtluo/libpolycrypto/polycommit"
	pb "github.com/zhtluo/libpolycrypto/proto"
	"google.golang.org/protobuf/proto"
)

var (
	MaxInt = bn256.Order
)

// Struct PublicInfo implements the public information available at the start of the phase.
type PublicInfo struct {
	Pk     polycommit.Pk
	Commit bn256.G2
}

// Struct Secret implements the secret the dealer wishes to share.
type Secret struct {
	Poly []big.Int
}

// Struct Secret implements the share of each node.
type Share struct {
	Index   big.Int
	Result  big.Int
	Witness bn256.G1
}

// Generate a secret with the constant term specified.
func GenerateSecret(r io.Reader, constant *big.Int, degree int) (*Secret, error) {
	s := new(Secret)
	s.Poly = make([]big.Int, degree)
	s.Poly[0] = *constant
	for i := 1; i < degree; i++ {
		r, err := rand.Int(r, bn256.Order)
		if err != nil {
			return nil, err
		}
		s.Poly[i] = *r
	}
	return s, nil
}

// Generate public information with the secret.
func GeneratePublicInfo(r io.Reader, s *Secret) (*PublicInfo, error) {
	pi := new(PublicInfo)
	err := pi.Pk.Setup(r, len(s.Poly))
	if err != nil {
		return nil, err
	}
	c, err := pi.Pk.Commit(s.Poly)
	pi.Commit = *c
	if err != nil {
		return nil, err
	}
	return pi, nil
}

// Generate a share based on the information and the secret.
func GenerateShare(pi *PublicInfo, s *Secret, index *big.Int) (*Share, error) {
	sh := new(Share)
	sh.Index = *index
	r, w, err := pi.Pk.CreateWitness(s.Poly, &sh.Index)
	if err != nil {
		return nil, err
	}
	sh.Result, sh.Witness = *r, *w
	return sh, nil
}

// Verify the received share with the public information.
func VerifyShare(pi *PublicInfo, sh *Share) bool {
	return pi.Pk.VerifyEval(&pi.Commit, &sh.Index, &sh.Result, &sh.Witness)
}

// Reconstruct the constant term of the secret with shares.
func ReconstructSecret(shs []Share) *big.Int {
	inverse := make([]big.Int, len(shs))
	for i := range inverse {
		inverse[i].ModInverse(&shs[i].Index, bn256.Order)
	}
	constant := big.NewInt(0)
	// Order + 1
	orders1 := new(big.Int).Add(bn256.Order, big.NewInt(1))
	for i := range shs {
		partial := new(big.Int).ModInverse(&shs[i].Result, bn256.Order)
		for j := range shs {
			if i != j {
				// p = p * (1 - x_i * x_j^-1)
				term := new(big.Int).Mul(&shs[i].Index, &inverse[j])
				term.Mod(term, bn256.Order)
				partial.Mul(partial, new(big.Int).Sub(orders1, term))
				partial.Mod(partial, bn256.Order)
			}
		}
		partial.ModInverse(partial, bn256.Order)
		constant.Mod(constant.Add(constant, partial), bn256.Order)
	}
	return constant
}

// Serialize the public infomation.
func (pi *PublicInfo) Marshal() ([]byte, error) {
	var sPi pb.PublicInfo
	var err error
	sPi.Pk, err = pi.Pk.Marshal()
	if err != nil {
		return nil, err
	}
	sPi.Commit = pi.Commit.Marshal()
	return proto.Marshal(&sPi)
}

// Deserialize the public infomation.
func (pi *PublicInfo) Unmarshal(b []byte) error {
	var sPi pb.PublicInfo
	err := proto.Unmarshal(b, &sPi)
	if err != nil {
		return err
	}
	if pi == nil {
		pi = new(PublicInfo)
	}
	err = pi.Pk.Unmarshal(sPi.Pk)
	if err != nil {
		return err
	}
	_, err = pi.Commit.Unmarshal(sPi.Commit)
	return err
}

// Serialize the share.
func (sh *Share) Marshal() ([]byte, error) {
	var sSh pb.Share
	sSh.Index = sh.Index.Bytes()
	sSh.Result = sh.Result.Bytes()
	sSh.Witness = sh.Witness.Marshal()
	return proto.Marshal(&sSh)
}

// Deserialize the share.
func (sh *Share) Unmarshal(b []byte) error {
	var sSh pb.Share
	err := proto.Unmarshal(b, &sSh)
	if err != nil {
		return err
	}
	if sh == nil {
		sh = new(Share)
	}
	sh.Index.SetBytes(sSh.Index)
	sh.Result.SetBytes(sSh.Result)
	_, err = sh.Witness.Unmarshal(sSh.Witness)
	return err
}

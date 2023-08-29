package jwz

import (
	"crypto/sha256"
	"math/big"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-iden3-crypto/utils"
)

// Hash returns poseidon hash of big.Int
// that was created from sha256 hash of the message bytes
// if such big.Int is not in the Field, DivMod result is returned.
func Hash(message []byte) (*big.Int, error) {

	// 1. sha256 hash
	h := sha256.New()
	_, err := h.Write(message)
	if err != nil {
		return nil, err
	}
	b := h.Sum(nil)

	// 2. swap hash before hashing

	bs := utils.SwapEndianness(b)
	bi := new(big.Int).SetBytes(bs)

	// 3. check if it's in field
	var m *big.Int
	if utils.CheckBigIntInField(bi) {
		m = bi
	} else {
		m = bi.Mod(bi, constants.Q)
	}

	// 2. poseidon
	res, err := poseidon.Hash([]*big.Int{m})

	if err != nil {
		return nil, err
	}
	return res, err
}

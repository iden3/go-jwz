package jwz

import (
	"crypto/sha256"
	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-iden3-crypto/utils"
	"math/big"
)

func PrepareMessageHash(message []byte) (*big.Int, error) {

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
	m := new(big.Int)
	if utils.CheckBigIntInField(bi) {
		m = bi
	} else {
		bi.DivMod(bi, constants.Q, m)
	}

	// 2. poseidon

	res, err := poseidon.Hash([]*big.Int{m})

	if err != nil {
		return nil, err
	}
	return res, err
}

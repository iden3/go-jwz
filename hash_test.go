package jwz

import (
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"math/big"
	"testing"
)

func TestHash(t *testing.T) {

	msg := "message"

	h, err := Hash([]byte(msg))
	require.NoError(t, err)

	assert.Equal(t, h.String(), "12195879903067908640854440056941289904003404799313352286287749481941648225513")
}

func TestPoseidonHash(t *testing.T) {
	msg := "message"

	toHash := new(big.Int).SetBytes([]byte(msg))

	i, err := poseidon.Hash([]*big.Int{toHash})
	require.NoError(t, err)
	assert.Equal(t, i.String(), "16076885786305451396952367807583087877643965039481491647404584414044042908412")

}

package jwz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/iden3/go-circuits"
	circuitsTesting "github.com/iden3/go-circuits/testing"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"math/big"
	"testing"
)

func MockPrepareAuthInputs(hash []byte, circuitID circuits.CircuitID) ([]byte, error) {
	privKeyHex := "28156abe7fe2fd433dc9df969286b96666489bac508612d0e16593e944c4f69f"

	challenge := new(big.Int).SetBytes(hash)

	identifier, claim, state, claimsTree, revTree, rootsTree, claimEntryMTP, claimNonRevMTP, signature, _ := circuitsTesting.AuthClaimFullInfo(context.Background(), privKeyHex, challenge)
	treeState := circuits.TreeState{
		State:          state,
		ClaimsRoot:     claimsTree.Root(),
		RevocationRoot: revTree.Root(),
		RootOfRoots:    rootsTree.Root(),
	}

	inputs := circuits.AuthInputs{
		ID: identifier,
		AuthClaim: circuits.Claim{
			Claim:       claim,
			Proof:       claimEntryMTP,
			TreeState:   treeState,
			NonRevProof: circuits.ClaimNonRevStatus{TreeState: treeState, Proof: claimNonRevMTP},
		},
		Signature: signature,
		Challenge: challenge,
	}
	return inputs.InputsMarshal()
}

func TestNewWithPayload(t *testing.T) {
	payload := []byte("mymessage")
	token, err := NewWithPayload(ProvingMethodGroth16AuthInstance, payload, MockPrepareAuthInputs)
	assert.NoError(t, err)

	assert.Equal(t, "groth16", token.Alg)
	assert.Equal(t, "auth", token.CircuitID)
	assert.Equal(t, []HeaderKey{headerCircuitID}, token.raw.Header[headerCritical])
	assert.Equal(t, "groth16", token.raw.Header[headerAlg])
}

func TestToken_Prove(t *testing.T) {
	payload := []byte("mymessage")
	token, err := NewWithPayload(ProvingMethodGroth16AuthInstance, payload, MockPrepareAuthInputs)
	assert.NoError(t, err)

	var provingKey, verificationKey, wasm []byte

	provingKey, err = ioutil.ReadFile("/tmp/auth/circuit_final.zkey")
	assert.Nil(t, err)

	wasm, err = ioutil.ReadFile("/tmp/auth/circuit.wasm")
	assert.Nil(t, err)

	verificationKey, err = ioutil.ReadFile("/tmp/auth/verification_key.json")
	assert.Nil(t, err)

	assert.NoError(t, err)

	tokenString, err := token.Prove(provingKey, wasm)

	assert.NoError(t, err)
	t.Log(tokenString)

	isValid, err := token.Verify(verificationKey)
	assert.NoError(t, err)
	assert.True(t, isValid)

}

func TestToken_Parse(t *testing.T) {

	token, err := Parse("eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjEzNTI4OTkwMDk0MDQxMTMzNzcwOTg3Njg3NzUzNzUxNjMzMTU4OTUwMTYwMTIwMjgzNTU0ODI0ODUwMzE4MDE4NTExNDYyMzI1NTciLCI3ODgwNDc1MzY2MjU3ODA4ODUzMTM1NDg4MDUwOTkyNTEyMzE3NzA3OTU2ODA3NTA0NzM2NTkwMzAwMTM0Njg3NTMzMjM4MDU4MTU3IiwiMSJdLCJwaV9iIjpbWyIxNzk0NTcxMzI1ODk1OTQ0OTIyMjk0NzUzMTIxNDQyOTk3ODY5NjIxMzg5NjEzNTU2MzAwNjIxOTgwNzg5MDg5NTU2MTE1MzE1Mjc2MiIsIjEzNDMwMzU3MDgyODc5Mjc0ODkzNTQ0MDI2NzU4MTkyNzU5NjUzMTkxOTU3NjI0MjkzOTMzMTAwMDY1NDcyMDgxMTcyNjY2NzA4MTUzIl0sWyIyMTU1NTEzMjkyMDk5MDUyMzMwMTYwNjM5ODQxMjMxNDYzMDI0MDAzNDM2NTAwODYxMjQwNzQ0MTU2MTMyMzA1MzYxNjA1MjcyMzA1IiwiMTAzNzYwMTMwMjA1ODIyMzQyOTMzNzE4MDc2NzU0MDg5OTcyNTk0ODczNjE5MzQ4OTY3ODYyNTQ0NzI3MjQ5MDk1NDI0NjYwMzA0NzgiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE4ODU1ODYxNzExMzMzNTUxOTgwMzAyNDk5ODg3NDg1MjUxNTU0NDc0NzI3OTQ4OTE4NzEzMDQwNTgzMjA1MjM1NjE3NTA5MTMyMzE5IiwiMTk3MjE5OTMwMjA0ODQzMDk1NDE5MzA2OTU2MTE3MDAwMTc4ODYyOTg2MjY4MjgwMDIyMTMyNDUwNzk4NzU4OTg1MTE1MDI2NzgxNzciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIxOTA1NDMzMzk3MDg4NTAyMzc4MDEyMzU2MDkzNjY3NTQ1NjcwMDg2MTQ2OTA2ODYwMzMyMTg4NDcxODc0ODk2MTc1MDkzMDQ2Njc5NCIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19")
	assert.NoError(t, err)

	var zkProof verifiable.ZKProof
	proofBytes, err := base64.StdEncoding.DecodeString("eyJwcm9vZiI6eyJwaV9hIjpbIjEzNTI4OTkwMDk0MDQxMTMzNzcwOTg3Njg3NzUzNzUxNjMzMTU4OTUwMTYwMTIwMjgzNTU0ODI0ODUwMzE4MDE4NTExNDYyMzI1NTciLCI3ODgwNDc1MzY2MjU3ODA4ODUzMTM1NDg4MDUwOTkyNTEyMzE3NzA3OTU2ODA3NTA0NzM2NTkwMzAwMTM0Njg3NTMzMjM4MDU4MTU3IiwiMSJdLCJwaV9iIjpbWyIxNzk0NTcxMzI1ODk1OTQ0OTIyMjk0NzUzMTIxNDQyOTk3ODY5NjIxMzg5NjEzNTU2MzAwNjIxOTgwNzg5MDg5NTU2MTE1MzE1Mjc2MiIsIjEzNDMwMzU3MDgyODc5Mjc0ODkzNTQ0MDI2NzU4MTkyNzU5NjUzMTkxOTU3NjI0MjkzOTMzMTAwMDY1NDcyMDgxMTcyNjY2NzA4MTUzIl0sWyIyMTU1NTEzMjkyMDk5MDUyMzMwMTYwNjM5ODQxMjMxNDYzMDI0MDAzNDM2NTAwODYxMjQwNzQ0MTU2MTMyMzA1MzYxNjA1MjcyMzA1IiwiMTAzNzYwMTMwMjA1ODIyMzQyOTMzNzE4MDc2NzU0MDg5OTcyNTk0ODczNjE5MzQ4OTY3ODYyNTQ0NzI3MjQ5MDk1NDI0NjYwMzA0NzgiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE4ODU1ODYxNzExMzMzNTUxOTgwMzAyNDk5ODg3NDg1MjUxNTU0NDc0NzI3OTQ4OTE4NzEzMDQwNTgzMjA1MjM1NjE3NTA5MTMyMzE5IiwiMTk3MjE5OTMwMjA0ODQzMDk1NDE5MzA2OTU2MTE3MDAwMTc4ODYyOTg2MjY4MjgwMDIyMTMyNDUwNzk4NzU4OTg1MTE1MDI2NzgxNzciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIxOTA1NDMzMzk3MDg4NTAyMzc4MDEyMzU2MDkzNjY3NTQ1NjcwMDg2MTQ2OTA2ODYwMzMyMTg4NDcxODc0ODk2MTc1MDkzMDQ2Njc5NCIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19")
	assert.NoError(t, err)
	err = json.Unmarshal(proofBytes, &zkProof)
	assert.NoError(t, err)

	payloadBytes, err := base64.StdEncoding.DecodeString("bXltZXNzYWdl")
	assert.NoError(t, err)

	assert.Equal(t, zkProof.PubSignals, token.ZkProof.PubSignals)
	assert.Equal(t, zkProof.Proof, token.ZkProof.Proof)
	assert.Equal(t, "auth", token.CircuitID)
	assert.Equal(t, "groth16", token.Alg)
	assert.Equal(t, payloadBytes, token.raw.Payload)

}

func TestToken_ParseWithOutputs(t *testing.T) {

	token, err := Parse("eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjEzNTI4OTkwMDk0MDQxMTMzNzcwOTg3Njg3NzUzNzUxNjMzMTU4OTUwMTYwMTIwMjgzNTU0ODI0ODUwMzE4MDE4NTExNDYyMzI1NTciLCI3ODgwNDc1MzY2MjU3ODA4ODUzMTM1NDg4MDUwOTkyNTEyMzE3NzA3OTU2ODA3NTA0NzM2NTkwMzAwMTM0Njg3NTMzMjM4MDU4MTU3IiwiMSJdLCJwaV9iIjpbWyIxNzk0NTcxMzI1ODk1OTQ0OTIyMjk0NzUzMTIxNDQyOTk3ODY5NjIxMzg5NjEzNTU2MzAwNjIxOTgwNzg5MDg5NTU2MTE1MzE1Mjc2MiIsIjEzNDMwMzU3MDgyODc5Mjc0ODkzNTQ0MDI2NzU4MTkyNzU5NjUzMTkxOTU3NjI0MjkzOTMzMTAwMDY1NDcyMDgxMTcyNjY2NzA4MTUzIl0sWyIyMTU1NTEzMjkyMDk5MDUyMzMwMTYwNjM5ODQxMjMxNDYzMDI0MDAzNDM2NTAwODYxMjQwNzQ0MTU2MTMyMzA1MzYxNjA1MjcyMzA1IiwiMTAzNzYwMTMwMjA1ODIyMzQyOTMzNzE4MDc2NzU0MDg5OTcyNTk0ODczNjE5MzQ4OTY3ODYyNTQ0NzI3MjQ5MDk1NDI0NjYwMzA0NzgiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE4ODU1ODYxNzExMzMzNTUxOTgwMzAyNDk5ODg3NDg1MjUxNTU0NDc0NzI3OTQ4OTE4NzEzMDQwNTgzMjA1MjM1NjE3NTA5MTMyMzE5IiwiMTk3MjE5OTMwMjA0ODQzMDk1NDE5MzA2OTU2MTE3MDAwMTc4ODYyOTg2MjY4MjgwMDIyMTMyNDUwNzk4NzU4OTg1MTE1MDI2NzgxNzciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIxOTA1NDMzMzk3MDg4NTAyMzc4MDEyMzU2MDkzNjY3NTQ1NjcwMDg2MTQ2OTA2ODYwMzMyMTg4NDcxODc0ODk2MTc1MDkzMDQ2Njc5NCIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19")
	assert.NoError(t, err)

	outs := circuits.AuthPubSignals{}
	err = token.ParsePubSignals(&outs)
	assert.NoError(t, err)

	assert.Equal(t, "119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ", outs.UserID.String())
	assert.Equal(t, "81d8df08abc3e9254b0becbf3d7b01d0f562e417adb4c13d453544485c013f29", outs.UserState.Hex())

	msgHash, err := token.GetMessageHash()
	assert.NoError(t, err)
	assert.Equal(t, msgHash, outs.Challenge.Bytes())
}

func TestToken_Verify(t *testing.T) {

	token, err := Parse("eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjYzMzY0ODgxNzk0NjAwNDc3NjAwMTcxMDIwMDU5ODQ0OTk5NzI0NTg3ODc2MzM5MjEyMTg3MTYyMzQ0MzMzMTkzOTE2ODA3ODkxNjkiLCIxODE5MzYwNjcwMzM3MjQwNDcwNTk2NjMwNjE2NTE0OTI4NDE5MDE5NjY4NDM2NTQ0OTY2MzA1NzA1MzM1MDc4MDQwNjAxMDU3ODgyNSIsIjEiXSwicGlfYiI6W1siNDc3NzAwNzIxMjU4NjUyOTc2NDk2MjcwNjE2NzM3MTU1ODUzNDA3NzY2MDg3Mjg1ODE2NjgwMzQ4ODc2MTU3NTYxNTU1NjcxNjAxMyIsIjEyMTk3ODk0NjEwNjU3MzA1MTg5MjE5OTg1NDA5OTA2NTM0MDkyNDQzNzU0MTQxNjE3OTAyMDQwMjYwMTgwNzM1MTY0Njk1NDUxMzc2Il0sWyIxMzI4NzQyNjMyNDAyMzEyMjAwMjk2MDY0Mzc4ODE0NjY4MzE4NzcxNzk0NDQwOTg1NDEzNDEwMTIyOTE4NDk5MDc2NDA4MTEyNDI1NSIsIjI2NTQ3NTMzMDY0NzgyODk2MzQyOTA3OTQxMDY1MjEzNzcyMzc1MjE2NDI5MzA2MTgwNTA0ODAzMzg3Njc1NTk5NDEwMTQyODQ5NTUiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjkzMjkwNzI2MzIwMDQ0OTAzMDc2MzEyNDE0ODEwNTQ2NDUyMzUzMTg2ODIwNjg1ODc3MDkzNjQyNzU5NTIxODUwNjE3OTM3NzgzOTMiLCIyNzM5ODMzMzc2MjExODEzNDY4NDExOTgzNzc4ODY4MTg4MDkxOTUxMjM2NDAxNTY3NjMyNDQ5NDQzMjc1NzgwOTMwOTEyNDkwMzA0IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMTkwNTQzMzM5NzA4ODUwMjM3ODAxMjM1NjA5MzY2NzU0NTY3MDA4NjE0NjkwNjg2MDMzMjE4ODQ3MTg3NDg5NjE3NTA5MzA0NjY3OTQiLCIxODY1NjE0NzU0NjY2Njk0NDQ4NDQ1Mzg5OTI0MTkxNjQ2OTU0NDA5MDI1ODgxMDE5MjgwMzk0OTUyMjc5NDQ5MDQ5MzI3MTAwNTMxMyIsIjM3OTk0OTE1MDEzMDIxNDcyMzQyMDU4OTYxMDkxMTE2MTg5NTQ5NTY0Nzc4OTAwNjY0OTc4NTI2NDczODE0MTI5OTEzNTQxNDI3MiJdfQ")
	assert.NoError(t, err)

	verificationKey, err := ioutil.ReadFile("/tmp/auth/verification_key.json")
	assert.Nil(t, err)

	isValid, err := token.Verify(verificationKey)
	assert.NoError(t, err)
	assert.True(t, isValid)

}

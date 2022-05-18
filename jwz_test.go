package jwz

import (
	"encoding/base64"
	"encoding/json"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func MockPrepareAuthInputs(hash []byte, circuitID circuits.CircuitID) ([]byte, error) {
	// hash is already signed
	return []byte(`{"userAuthClaim":["304427537360709784173770334266246861770","0","17640206035128972995519606214765283372613874593503528180869261482403155458945","20634138280259599560273310290025659992320584624461316485434108770067472477956","15930428023331155902","0","0","0"],"userAuthClaimMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"userAuthClaimNonRevMtpAuxHi":"0","userAuthClaimNonRevMtpAuxHv":"0","userAuthClaimNonRevMtpNoAux":"1","challenge":"19054333970885023780123560936675456700861469068603321884718748961750930466794","challengeSignatureR8x":"4219150445599866015975338408000561684366422973912091598548631071677167824366","challengeSignatureR8y":"12598735963096034383552425395289278326931986118036778264141841465661466935045","challengeSignatureS":"482456738038705898703405023807226003538372788878082557708969187456494192709","userClaimsTreeRoot":"9763429684850732628215303952870004997159843236039795272605841029866455670219","userID":"379949150130214723420589610911161895495647789006649785264738141299135414272","userRevTreeRoot":"0","userRootsTreeRoot":"0","userState":"18656147546666944484453899241916469544090258810192803949522794490493271005313"}`), nil
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

	provingKey, err = os.ReadFile("./testdata/circuit_final.zkey")
	assert.Nil(t, err)

	wasm, err = os.ReadFile("./testdata/circuit.wasm")
	assert.Nil(t, err)

	verificationKey, err = os.ReadFile("./testdata/verification_key.json")
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

	var zkProof types.ZKProof
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

package jwz

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/stretchr/testify/assert"
)

func MockPrepareAuthV2Inputs(_ []byte, _ circuits.CircuitID) ([]byte, error) {
	// hash is already signed
	return []byte(`{"genesisID":"19229084873704550357232887142774605442297337229176579229011342091594174977","profileNonce":"0","authClaim":["301485908906857522017021291028488077057","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"6110517768249559238193477435454792024732173865488900270849624328650765691494","challengeSignatureR8x":"10923900855019966925146890192107445603460581432515833977084358496785417078889","challengeSignatureR8y":"16158862443157007045624936621448425746188316255879806600364391221203989186031","challengeSignatureS":"51416591880507739389339515804072924841765472826035808894700970942045022090","claimsTreeRoot":"5156125448952672817978035354327403409438120028299513459509442000229340486813","revTreeRoot":"0","rootsTreeRoot":"0","state":"13749793311041076104545663747883540987785640262360452307923674522221753800226","gistRoot":"1243904711429961858774220647610724273798918457991486031567244100767259239747","gistMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"1","gistMtpAuxHv":"1","gistMtpNoAux":"0"}`), nil
}

func TestNewWithPayload(t *testing.T) {
	payload := []byte("mymessage")
	token, err := NewWithPayload(ProvingMethodGroth16AuthV2Instance, payload, MockPrepareAuthV2Inputs)
	assert.NoError(t, err)

	assert.Equal(t, "groth16", token.Alg)
	assert.Equal(t, "authV2", token.CircuitID)
	assert.Equal(t, []HeaderKey{headerCircuitID}, token.raw.Header[headerCritical])
	assert.Equal(t, "groth16", token.raw.Header[headerAlg])
}

func TestToken_Prove(t *testing.T) {

	payload := []byte("mymessage")
	token, err := NewWithPayload(ProvingMethodGroth16AuthV2Instance, payload, MockPrepareAuthV2Inputs)
	assert.NoError(t, err)

	var provingKey, verificationKey, wasm []byte

	provingKey, err = os.ReadFile("./testdata/authV2/circuit_final.zkey")
	assert.Nil(t, err)

	wasm, err = os.ReadFile("./testdata/authV2/circuit.wasm")
	assert.Nil(t, err)

	verificationKey, err = os.ReadFile("./testdata/authV2/verification_key.json")
	assert.Nil(t, err)

	assert.NoError(t, err)

	tokenString, err := token.Prove(provingKey, wasm)

	assert.NoError(t, err)
	t.Log(tokenString)

	isValid, err := token.Verify(verificationKey)
	assert.NoError(t, err)
	assert.True(t, isValid)

}

func BenchmarkToken_Prove(b *testing.B) {
	payload := []byte("mymessage")
	token, err := NewWithPayload(ProvingMethodGroth16AuthV2Instance, payload, MockPrepareAuthV2Inputs)
	assert.NoError(b, err)

	var provingKey, verificationKey, wasm []byte

	provingKey, err = os.ReadFile("./testdata/authV2/circuit_final.zkey")
	assert.Nil(b, err)

	wasm, err = os.ReadFile("./testdata/authV2/circuit.wasm")
	assert.Nil(b, err)

	verificationKey, err = os.ReadFile("./testdata/authV2/verification_key.json")
	assert.NoError(b, err)

	for i := 0; i < b.N; i++ {
		_, err = token.Prove(provingKey, wasm)
		assert.NoError(b, err)

		isValid, err := token.Verify(verificationKey)
		assert.NoError(b, err)
		assert.True(b, isValid)
	}
}

func TestToken_Parse(t *testing.T) {

	token, err := Parse("eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjE5MTU5MDg5MTAwMDkzNDQyMzY0NTY0MjQxOTA3ODQ1MzkxODgxMzM5NDQ3NDkxNTcwNjg2NTk5NDE3MjA0MzUwNTE1ODE0NzYxNDE1IiwiNDQ4MDg2MzgzNDY4MTU2ODM2MTI2NTI1NzgzMzkyMjk1OTE1Mzg5OTQwNDUzMDkxNjcxNTA5NjEyMzg3NTU1MzY0NjM3NjMwNTQzOSIsIjEiXSwicGlfYiI6W1siMTA3MjY0OTYxNTk4OTQwNDAyNTExMDYyMDkyOTA5MjUzOTQ3MDU1MTk0NTYyNTkyMDYwNjgxMTE0MTY4ODQyMDI2MzI0MzY4Nzk1MDAiLCIzODkwMTY0OTc1OTMzOTQzMDY2NTc5ODI3OTk2MDcxNzI0NDg5NjEwNDU1ODQ0NTU5NDQ2MDIwMTk4ODQyNDQwNzk5MzAyNzQyOTk5Il0sWyIxOTY4NjI5MDk3ODAzMzI1MTU1MjczMjAzNTMxMzIyODYwNTE0Mzc3OTUwOTkwNTk1OTAxMTcxODUwNDI1ODQ3NjgxNzY0MzU2NTM1IiwiNDU2OTY3NjE1OTg3MjgwNDYwOTQzMzcyMTcxODAxNjc2MzE2NDczNTQwMzA5Njg4NjE1OTIxMTg0NjA1MDE3MDY1OTk1MTE3NjU4MSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTc4ODM0NTM4NjIxNDI2ODI2MjUwNjI3MDA5NTEzMTU0ODQ4OTUyMDA0OTI3MDgwOTk4MzcwNzM1NjAyNzYxNzk4OTM5MzQ5NzQ2MjEiLCI3NzU4ODI2NjAwNTM2MDU3MDUwNTc2MDMxMDE4NjQ0MDk4NjQyODMxMTE5MzQ2ODM3NjgyMTMzNDU5MjgyMjg4NzExMjgyMzA2NjM4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMTkyMjkwODQ4NzM3MDQ1NTAzNTcyMzI4ODcxNDI3NzQ2MDU0NDIyOTczMzcyMjkxNzY1NzkyMjkwMTEzNDIwOTE1OTQxNzQ5NzciLCI2MTEwNTE3NzY4MjQ5NTU5MjM4MTkzNDc3NDM1NDU0NzkyMDI0NzMyMTczODY1NDg4OTAwMjcwODQ5NjI0MzI4NjUwNzY1NjkxNDk0IiwiMTI0MzkwNDcxMTQyOTk2MTg1ODc3NDIyMDY0NzYxMDcyNDI3Mzc5ODkxODQ1Nzk5MTQ4NjAzMTU2NzI0NDEwMDc2NzI1OTIzOTc0NyJdfQ")
	assert.NoError(t, err)

	var zkProof types.ZKProof
	proofBytes, err := base64.RawURLEncoding.DecodeString("eyJwcm9vZiI6eyJwaV9hIjpbIjE5MTU5MDg5MTAwMDkzNDQyMzY0NTY0MjQxOTA3ODQ1MzkxODgxMzM5NDQ3NDkxNTcwNjg2NTk5NDE3MjA0MzUwNTE1ODE0NzYxNDE1IiwiNDQ4MDg2MzgzNDY4MTU2ODM2MTI2NTI1NzgzMzkyMjk1OTE1Mzg5OTQwNDUzMDkxNjcxNTA5NjEyMzg3NTU1MzY0NjM3NjMwNTQzOSIsIjEiXSwicGlfYiI6W1siMTA3MjY0OTYxNTk4OTQwNDAyNTExMDYyMDkyOTA5MjUzOTQ3MDU1MTk0NTYyNTkyMDYwNjgxMTE0MTY4ODQyMDI2MzI0MzY4Nzk1MDAiLCIzODkwMTY0OTc1OTMzOTQzMDY2NTc5ODI3OTk2MDcxNzI0NDg5NjEwNDU1ODQ0NTU5NDQ2MDIwMTk4ODQyNDQwNzk5MzAyNzQyOTk5Il0sWyIxOTY4NjI5MDk3ODAzMzI1MTU1MjczMjAzNTMxMzIyODYwNTE0Mzc3OTUwOTkwNTk1OTAxMTcxODUwNDI1ODQ3NjgxNzY0MzU2NTM1IiwiNDU2OTY3NjE1OTg3MjgwNDYwOTQzMzcyMTcxODAxNjc2MzE2NDczNTQwMzA5Njg4NjE1OTIxMTg0NjA1MDE3MDY1OTk1MTE3NjU4MSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTc4ODM0NTM4NjIxNDI2ODI2MjUwNjI3MDA5NTEzMTU0ODQ4OTUyMDA0OTI3MDgwOTk4MzcwNzM1NjAyNzYxNzk4OTM5MzQ5NzQ2MjEiLCI3NzU4ODI2NjAwNTM2MDU3MDUwNTc2MDMxMDE4NjQ0MDk4NjQyODMxMTE5MzQ2ODM3NjgyMTMzNDU5MjgyMjg4NzExMjgyMzA2NjM4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMTkyMjkwODQ4NzM3MDQ1NTAzNTcyMzI4ODcxNDI3NzQ2MDU0NDIyOTczMzcyMjkxNzY1NzkyMjkwMTEzNDIwOTE1OTQxNzQ5NzciLCI2MTEwNTE3NzY4MjQ5NTU5MjM4MTkzNDc3NDM1NDU0NzkyMDI0NzMyMTczODY1NDg4OTAwMjcwODQ5NjI0MzI4NjUwNzY1NjkxNDk0IiwiMTI0MzkwNDcxMTQyOTk2MTg1ODc3NDIyMDY0NzYxMDcyNDI3Mzc5ODkxODQ1Nzk5MTQ4NjAzMTU2NzI0NDEwMDc2NzI1OTIzOTc0NyJdfQ")
	assert.NoError(t, err)
	err = json.Unmarshal(proofBytes, &zkProof)
	assert.NoError(t, err)

	payloadBytes, err := base64.RawURLEncoding.DecodeString("bXltZXNzYWdl")
	assert.NoError(t, err)

	assert.Equal(t, zkProof.PubSignals, token.ZkProof.PubSignals)
	assert.Equal(t, zkProof.Proof, token.ZkProof.Proof)
	assert.Equal(t, "authV2", token.CircuitID)
	assert.Equal(t, "groth16", token.Alg)
	assert.Equal(t, payloadBytes, token.raw.Payload)

}

func TestToken_ParseWithOutputs(t *testing.T) {

	token, err := Parse("eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjE5MTU5MDg5MTAwMDkzNDQyMzY0NTY0MjQxOTA3ODQ1MzkxODgxMzM5NDQ3NDkxNTcwNjg2NTk5NDE3MjA0MzUwNTE1ODE0NzYxNDE1IiwiNDQ4MDg2MzgzNDY4MTU2ODM2MTI2NTI1NzgzMzkyMjk1OTE1Mzg5OTQwNDUzMDkxNjcxNTA5NjEyMzg3NTU1MzY0NjM3NjMwNTQzOSIsIjEiXSwicGlfYiI6W1siMTA3MjY0OTYxNTk4OTQwNDAyNTExMDYyMDkyOTA5MjUzOTQ3MDU1MTk0NTYyNTkyMDYwNjgxMTE0MTY4ODQyMDI2MzI0MzY4Nzk1MDAiLCIzODkwMTY0OTc1OTMzOTQzMDY2NTc5ODI3OTk2MDcxNzI0NDg5NjEwNDU1ODQ0NTU5NDQ2MDIwMTk4ODQyNDQwNzk5MzAyNzQyOTk5Il0sWyIxOTY4NjI5MDk3ODAzMzI1MTU1MjczMjAzNTMxMzIyODYwNTE0Mzc3OTUwOTkwNTk1OTAxMTcxODUwNDI1ODQ3NjgxNzY0MzU2NTM1IiwiNDU2OTY3NjE1OTg3MjgwNDYwOTQzMzcyMTcxODAxNjc2MzE2NDczNTQwMzA5Njg4NjE1OTIxMTg0NjA1MDE3MDY1OTk1MTE3NjU4MSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTc4ODM0NTM4NjIxNDI2ODI2MjUwNjI3MDA5NTEzMTU0ODQ4OTUyMDA0OTI3MDgwOTk4MzcwNzM1NjAyNzYxNzk4OTM5MzQ5NzQ2MjEiLCI3NzU4ODI2NjAwNTM2MDU3MDUwNTc2MDMxMDE4NjQ0MDk4NjQyODMxMTE5MzQ2ODM3NjgyMTMzNDU5MjgyMjg4NzExMjgyMzA2NjM4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMTkyMjkwODQ4NzM3MDQ1NTAzNTcyMzI4ODcxNDI3NzQ2MDU0NDIyOTczMzcyMjkxNzY1NzkyMjkwMTEzNDIwOTE1OTQxNzQ5NzciLCI2MTEwNTE3NzY4MjQ5NTU5MjM4MTkzNDc3NDM1NDU0NzkyMDI0NzMyMTczODY1NDg4OTAwMjcwODQ5NjI0MzI4NjUwNzY1NjkxNDk0IiwiMTI0MzkwNDcxMTQyOTk2MTg1ODc3NDIyMDY0NzYxMDcyNDI3Mzc5ODkxODQ1Nzk5MTQ4NjAzMTU2NzI0NDEwMDc2NzI1OTIzOTc0NyJdfQ")
	assert.NoError(t, err)

	outs := circuits.AuthV2PubSignals{}
	err = token.ParsePubSignals(&outs)
	assert.NoError(t, err)

	assert.Equal(t, "x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29", outs.UserID.String())
	assert.Equal(t, "4325bf7386b102c223cd6109e3b6b1bc813ecb14b2c3332bbd2aa7106e06c002", outs.GISTRoot.Hex())

	msgHash, err := token.GetMessageHash()
	assert.NoError(t, err)
	assert.Equal(t, msgHash, outs.Challenge.Bytes())

	did, err := core.ParseDIDFromID(*outs.UserID)
	assert.NoError(t, err)
	assert.Equal(t, "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29", did.String())

}

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

func MockPrepareAuthV3Inputs(_ []byte, _ circuits.CircuitID) ([]byte, error) {
	// hash is already signed
	return []byte(`{"genesisID":"23273167900576580892722615617815475823351560716009055944677723144398443009","profileNonce":"0","authClaim":["80551937543569765027552589160822318028","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["20643387758736831799596675626240785455902781070167728593409367019626753600795","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"15997052917246064036592446616808680316677720366381306147286202311286142126826","challengeSignatureR8x":"14814416808449860798229850027466815499618347907194745718733221355391260028283","challengeSignatureR8y":"4112444211451581299965320230239613118199750678931648705294867682050395522623","challengeSignatureS":"2201595010244638725232493661689550828769979367760557441084895625977276980737","claimsTreeRoot":"8794724428328826645726823821449086761079599815895679828313419678997386356573","revTreeRoot":"0","rootsTreeRoot":"0","state":"7115004997868594253010848596868364067574661249707337517331323113105592633327","gistRoot":"20746967949242970504735775681024928984312199406892280437050499102607067526238","gistMtp":["0","0","0","1243904711429961858774220647610724273798918457991486031567244100767259239747","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"0","gistMtpAuxHv":"0","gistMtpNoAux":"0"}`), nil
}

func MockPrepareAuthV3_8_32Inputs(_ []byte, _ circuits.CircuitID) ([]byte, error) {
	// hash is already signed
	return []byte(`{"genesisID":"23273167900576580892722615617815475823351560716009055944677723144398443009","profileNonce":"0","authClaim":["80551937543569765027552589160822318028","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["20643387758736831799596675626240785455902781070167728593409367019626753600795","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"6807542932739626352372202747650479413343284843713199903849051801035429042865","challengeSignatureR8x":"7525126381917356257636372917552188361117494179201353025019127810758731021916","challengeSignatureR8y":"20415806316264090304714063012907270619258996127071363004039215148633807127483","challengeSignatureS":"251992476641732412701642926724758498615919121424404336076731271483813524620","claimsTreeRoot":"8794724428328826645726823821449086761079599815895679828313419678997386356573","revTreeRoot":"0","rootsTreeRoot":"0","state":"7115004997868594253010848596868364067574661249707337517331323113105592633327","gistRoot":"20746967949242970504735775681024928984312199406892280437050499102607067526238","gistMtp":["0","0","0","1243904711429961858774220647610724273798918457991486031567244100767259239747","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"0","gistMtpAuxHv":"0","gistMtpNoAux":"0"}`), nil
}

// Auth v2
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

// Auth v3
func TestAuthV3NewWithPayload(t *testing.T) {
	payload := []byte("mymessage")
	token, err := NewWithPayload(ProvingMethodGroth16AuthV3Instance, payload, MockPrepareAuthV3Inputs)
	assert.NoError(t, err)

	assert.Equal(t, "groth16", token.Alg)
	assert.Equal(t, "authV3", token.CircuitID)
	assert.Equal(t, []HeaderKey{headerCircuitID}, token.raw.Header[headerCritical])
	assert.Equal(t, "groth16", token.raw.Header[headerAlg])
}

func TestTokenAuthV3_Prove(t *testing.T) {
	payload := []byte("mymessage")
	token, err := NewWithPayload(ProvingMethodGroth16AuthV3Instance, payload, MockPrepareAuthV3Inputs)
	assert.NoError(t, err)

	var provingKey, verificationKey, wasm []byte

	provingKey, err = os.ReadFile("./testdata/authV3/circuit_final.zkey")
	assert.Nil(t, err)

	wasm, err = os.ReadFile("./testdata/authV3/circuit.wasm")
	assert.Nil(t, err)

	verificationKey, err = os.ReadFile("./testdata/authV3/verification_key.json")
	assert.Nil(t, err)

	assert.NoError(t, err)

	tokenString, err := token.Prove(provingKey, wasm)

	assert.NoError(t, err)
	t.Log(tokenString)

	isValid, err := token.Verify(verificationKey)
	assert.NoError(t, err)
	assert.True(t, isValid)
}

func BenchmarkTokenAuthV3_Prove(b *testing.B) {
	payload := []byte("mymessage")
	token, err := NewWithPayload(ProvingMethodGroth16AuthV3Instance, payload, MockPrepareAuthV3Inputs)
	assert.NoError(b, err)

	var provingKey, verificationKey, wasm []byte

	provingKey, err = os.ReadFile("./testdata/authV3/circuit_final.zkey")
	assert.Nil(b, err)

	wasm, err = os.ReadFile("./testdata/authV3/circuit.wasm")
	assert.Nil(b, err)

	verificationKey, err = os.ReadFile("./testdata/authV3/verification_key.json")
	assert.NoError(b, err)

	for i := 0; i < b.N; i++ {
		_, err = token.Prove(provingKey, wasm)
		assert.NoError(b, err)

		isValid, err := token.Verify(verificationKey)
		assert.NoError(b, err)
		assert.True(b, isValid)
	}
}

func TestTokenAuthV3_Parse(t *testing.T) {
	token, err := Parse("eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYzIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjE1NTkyNjM2NDQ2MTcwNzcyNDc3NDEyMjI0OTIzNTM2OTg1MDA5OTc4MDE2MTg4MjMyOTkzODA5ODA3MzUzNjU4MjgxNjIxMDYwNDg5IiwiMTI5MzU1MjA3NzczNDc1Mjk5NTQyNDY2NDQ0MTgwNTM2OTYxMTc4OTMwNTUzMDMyNzgzNjMyNTQxNzk3NzU2ODE5OTkyNzQ1NDYxMzUiLCIxIl0sInBpX2IiOltbIjE5Mjc2ODU1ODY2MTQ3NjA4MDE5MDIwMDI5NTEwMzg3NDMwODQxNjcxMzM0NDM4ODM0MTg0NTEwMTkyNTI0MjAxNDU5MjEyNTEyMTEiLCIxODAwODM4NjQ5MDMyNDcxNTA1OTMxNjQ0MjExNjk3MDcyNDIxMDY2MjU5ODIwNDkxMzczNzc5Mjk4MDkzMTA5NTY4ODEzNzk3NjAxOCJdLFsiNDY1MjQyMTA1NjIwNzEyMTQ3MDc1MjQ5MDEyMTgyMzQxMjMwNzM3MjMwMDE5MTY3NzQwNjI1MjQxMjMxMDc0ODM3NTkzNTUxMTUzMCIsIjQ4OTg4MDM2NDU0OTYyNzExOTA2MTIxMTA5MDAzMjE2MDE2NjQwMTYxMjUzMjk3NTI5NjMyNDQ4NDY5OTYzNzU0Njk0MTAwNzA3NjUiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjc4ODM3OTQ3OTE3NDUyNTkzNTM0OTc4NzgyMzQ3NDk2MjE4NzYwNTcwODQ3MDE1MDAwMDQyNTMwNTQxMDMwNDkzNjcxNjczMDQ5MTgiLCI2ODU3MTgwNDQwNDMwNDk1NDc4MzkwNTA5NDQ5NzUzNjYxODM2NzkyMDAwMTc4MTU3OTA2NTM1MzUzNDkxMDYwMzM2MTE4NDg4ODgiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjMyNzMxNjc5MDA1NzY1ODA4OTI3MjI2MTU2MTc4MTU0NzU4MjMzNTE1NjA3MTYwMDkwNTU5NDQ2Nzc3MjMxNDQzOTg0NDMwMDkiLCIxNTk5NzA1MjkxNzI0NjA2NDAzNjU5MjQ0NjYxNjgwODY4MDMxNjY3NzcyMDM2NjM4MTMwNjE0NzI4NjIwMjMxMTI4NjE0MjEyNjgyNiIsIjIwNzQ2OTY3OTQ5MjQyOTcwNTA0NzM1Nzc1NjgxMDI0OTI4OTg0MzEyMTk5NDA2ODkyMjgwNDM3MDUwNDk5MTAyNjA3MDY3NTI2MjM4Il19")
	assert.NoError(t, err)

	var zkProof types.ZKProof
	proofBytes, err := base64.RawURLEncoding.DecodeString("eyJwcm9vZiI6eyJwaV9hIjpbIjE1NTkyNjM2NDQ2MTcwNzcyNDc3NDEyMjI0OTIzNTM2OTg1MDA5OTc4MDE2MTg4MjMyOTkzODA5ODA3MzUzNjU4MjgxNjIxMDYwNDg5IiwiMTI5MzU1MjA3NzczNDc1Mjk5NTQyNDY2NDQ0MTgwNTM2OTYxMTc4OTMwNTUzMDMyNzgzNjMyNTQxNzk3NzU2ODE5OTkyNzQ1NDYxMzUiLCIxIl0sInBpX2IiOltbIjE5Mjc2ODU1ODY2MTQ3NjA4MDE5MDIwMDI5NTEwMzg3NDMwODQxNjcxMzM0NDM4ODM0MTg0NTEwMTkyNTI0MjAxNDU5MjEyNTEyMTEiLCIxODAwODM4NjQ5MDMyNDcxNTA1OTMxNjQ0MjExNjk3MDcyNDIxMDY2MjU5ODIwNDkxMzczNzc5Mjk4MDkzMTA5NTY4ODEzNzk3NjAxOCJdLFsiNDY1MjQyMTA1NjIwNzEyMTQ3MDc1MjQ5MDEyMTgyMzQxMjMwNzM3MjMwMDE5MTY3NzQwNjI1MjQxMjMxMDc0ODM3NTkzNTUxMTUzMCIsIjQ4OTg4MDM2NDU0OTYyNzExOTA2MTIxMTA5MDAzMjE2MDE2NjQwMTYxMjUzMjk3NTI5NjMyNDQ4NDY5OTYzNzU0Njk0MTAwNzA3NjUiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjc4ODM3OTQ3OTE3NDUyNTkzNTM0OTc4NzgyMzQ3NDk2MjE4NzYwNTcwODQ3MDE1MDAwMDQyNTMwNTQxMDMwNDkzNjcxNjczMDQ5MTgiLCI2ODU3MTgwNDQwNDMwNDk1NDc4MzkwNTA5NDQ5NzUzNjYxODM2NzkyMDAwMTc4MTU3OTA2NTM1MzUzNDkxMDYwMzM2MTE4NDg4ODgiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjMyNzMxNjc5MDA1NzY1ODA4OTI3MjI2MTU2MTc4MTU0NzU4MjMzNTE1NjA3MTYwMDkwNTU5NDQ2Nzc3MjMxNDQzOTg0NDMwMDkiLCIxNTk5NzA1MjkxNzI0NjA2NDAzNjU5MjQ0NjYxNjgwODY4MDMxNjY3NzcyMDM2NjM4MTMwNjE0NzI4NjIwMjMxMTI4NjE0MjEyNjgyNiIsIjIwNzQ2OTY3OTQ5MjQyOTcwNTA0NzM1Nzc1NjgxMDI0OTI4OTg0MzEyMTk5NDA2ODkyMjgwNDM3MDUwNDk5MTAyNjA3MDY3NTI2MjM4Il19")
	assert.NoError(t, err)
	err = json.Unmarshal(proofBytes, &zkProof)
	assert.NoError(t, err)

	payloadBytes, err := base64.RawURLEncoding.DecodeString("bXltZXNzYWdl")
	assert.NoError(t, err)

	assert.Equal(t, zkProof.PubSignals, token.ZkProof.PubSignals)
	assert.Equal(t, zkProof.Proof, token.ZkProof.Proof)
	assert.Equal(t, "authV3", token.CircuitID)
	assert.Equal(t, "groth16", token.Alg)
	assert.Equal(t, payloadBytes, token.raw.Payload)
}

func TestTokenAuthV3_ParseWithOutputs(t *testing.T) {
	token, err := Parse("eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYzIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjE1NTkyNjM2NDQ2MTcwNzcyNDc3NDEyMjI0OTIzNTM2OTg1MDA5OTc4MDE2MTg4MjMyOTkzODA5ODA3MzUzNjU4MjgxNjIxMDYwNDg5IiwiMTI5MzU1MjA3NzczNDc1Mjk5NTQyNDY2NDQ0MTgwNTM2OTYxMTc4OTMwNTUzMDMyNzgzNjMyNTQxNzk3NzU2ODE5OTkyNzQ1NDYxMzUiLCIxIl0sInBpX2IiOltbIjE5Mjc2ODU1ODY2MTQ3NjA4MDE5MDIwMDI5NTEwMzg3NDMwODQxNjcxMzM0NDM4ODM0MTg0NTEwMTkyNTI0MjAxNDU5MjEyNTEyMTEiLCIxODAwODM4NjQ5MDMyNDcxNTA1OTMxNjQ0MjExNjk3MDcyNDIxMDY2MjU5ODIwNDkxMzczNzc5Mjk4MDkzMTA5NTY4ODEzNzk3NjAxOCJdLFsiNDY1MjQyMTA1NjIwNzEyMTQ3MDc1MjQ5MDEyMTgyMzQxMjMwNzM3MjMwMDE5MTY3NzQwNjI1MjQxMjMxMDc0ODM3NTkzNTUxMTUzMCIsIjQ4OTg4MDM2NDU0OTYyNzExOTA2MTIxMTA5MDAzMjE2MDE2NjQwMTYxMjUzMjk3NTI5NjMyNDQ4NDY5OTYzNzU0Njk0MTAwNzA3NjUiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjc4ODM3OTQ3OTE3NDUyNTkzNTM0OTc4NzgyMzQ3NDk2MjE4NzYwNTcwODQ3MDE1MDAwMDQyNTMwNTQxMDMwNDkzNjcxNjczMDQ5MTgiLCI2ODU3MTgwNDQwNDMwNDk1NDc4MzkwNTA5NDQ5NzUzNjYxODM2NzkyMDAwMTc4MTU3OTA2NTM1MzUzNDkxMDYwMzM2MTE4NDg4ODgiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjMyNzMxNjc5MDA1NzY1ODA4OTI3MjI2MTU2MTc4MTU0NzU4MjMzNTE1NjA3MTYwMDkwNTU5NDQ2Nzc3MjMxNDQzOTg0NDMwMDkiLCIxNTk5NzA1MjkxNzI0NjA2NDAzNjU5MjQ0NjYxNjgwODY4MDMxNjY3NzcyMDM2NjM4MTMwNjE0NzI4NjIwMjMxMTI4NjE0MjEyNjgyNiIsIjIwNzQ2OTY3OTQ5MjQyOTcwNTA0NzM1Nzc1NjgxMDI0OTI4OTg0MzEyMTk5NDA2ODkyMjgwNDM3MDUwNDk5MTAyNjA3MDY3NTI2MjM4Il19")
	assert.NoError(t, err)

	outs := circuits.AuthV3PubSignals{}
	err = token.ParsePubSignals(&outs)
	assert.NoError(t, err)

	assert.Equal(t, "wuzLSsUkkPdMn16Md8uHLKnfw9b3GB7gLLheTJfSc", outs.UserID.String())
	assert.Equal(t, "5e3463f1f0624decb3fa263df062bbf5af019e3092ed541a8bd42441235ede2d", outs.GISTRoot.Hex())

	msgHash, err := token.GetMessageHash()
	assert.NoError(t, err)
	assert.Equal(t, msgHash, outs.Challenge.Bytes())

	did, err := core.ParseDIDFromID(*outs.UserID)
	assert.NoError(t, err)
	assert.Equal(t, "did:iden3:polygon:mumbai:wuzLSsUkkPdMn16Md8uHLKnfw9b3GB7gLLheTJfSc", did.String())
}

func TestTokenAuthV3_8_32__DynamicProve(t *testing.T) {
	payload := []byte("mymessage")

	token, err := NewWithPayload(ProvingMethodGroth16AuthV3Instance, payload, MockPrepareAuthV3_8_32Inputs)
	assert.NoError(t, err)

	var provingKey, verificationKey, wasm []byte

	provingKey, err = os.ReadFile("./testdata/authV3-8-32/circuit_final.zkey")
	assert.Nil(t, err)

	wasm, err = os.ReadFile("./testdata/authV3-8-32/circuit.wasm")
	assert.Nil(t, err)

	verificationKey, err = os.ReadFile("./testdata/authV3-8-32/verification_key.json")
	assert.Nil(t, err)

	assert.NoError(t, err)

	tokenString, err := token.DynamicProve(
		[]ProvingParam{
			{
				CircuitID:  "authV3-8-32",
				ProvingKey: provingKey,
				Wasm:       wasm,
			},
		},
		func(msgHash []byte) ([]byte, string, error) {
			// inp, err := token.inputsPreparer.Prepare(msgHash, circuits.CircuitID("authV3-8-32"))
			return []byte(`{"genesisID":"23273167900576580892722615617815475823351560716009055944677723144398443009","profileNonce":"0","authClaim":["80551937543569765027552589160822318028","0","4720763745722683616702324599137259461509439547324750011830105416383780791263","4844030361230692908091131578688419341633213823133966379083981236400104720538","16547485850637761685","0","0","0"],"authClaimIncMtp":["20643387758736831799596675626240785455902781070167728593409367019626753600795","0","0","0","0","0","0","0"],"authClaimNonRevMtp":["0","0","0","0","0","0","0","0"],"authClaimNonRevMtpAuxHi":"0","authClaimNonRevMtpAuxHv":"0","authClaimNonRevMtpNoAux":"1","challenge":"6807542932739626352372202747650479413343284843713199903849051801035429042865","challengeSignatureR8x":"7525126381917356257636372917552188361117494179201353025019127810758731021916","challengeSignatureR8y":"20415806316264090304714063012907270619258996127071363004039215148633807127483","challengeSignatureS":"251992476641732412701642926724758498615919121424404336076731271483813524620","claimsTreeRoot":"8794724428328826645726823821449086761079599815895679828313419678997386356573","revTreeRoot":"0","rootsTreeRoot":"0","state":"7115004997868594253010848596868364067574661249707337517331323113105592633327","gistRoot":"20746967949242970504735775681024928984312199406892280437050499102607067526238","gistMtp":["0","0","0","1243904711429961858774220647610724273798918457991486031567244100767259239747","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],"gistMtpAuxHi":"0","gistMtpAuxHv":"0","gistMtpNoAux":"0"}`), "authV3-8-32", err
		},
	)

	assert.NoError(t, err)
	t.Log(tokenString)

	isValid, err := token.DynamicVerify([]VerificationKeyParam{
		{
			CircuitID:       "authV3-8-32",
			VerificationKey: verificationKey,
		},
	})
	assert.NoError(t, err)
	assert.True(t, isValid)
}

func BenchmarkTokenAuthV3_8_32__Prove(b *testing.B) {
	payload := []byte("mymessage")
	token, err := NewWithPayload(ProvingMethodGroth16AuthV3Instance, payload, MockPrepareAuthV3_8_32Inputs)
	assert.NoError(b, err)

	var provingKey, verificationKey, wasm []byte

	provingKey, err = os.ReadFile("./testdata/authV3-8-32/circuit_final.zkey")
	assert.Nil(b, err)

	wasm, err = os.ReadFile("./testdata/authV3-8-32/circuit.wasm")
	assert.Nil(b, err)

	verificationKey, err = os.ReadFile("./testdata/authV3-8-32/verification_key.json")
	assert.NoError(b, err)

	for i := 0; i < b.N; i++ {
		_, err = token.Prove(provingKey, wasm)
		assert.NoError(b, err)

		isValid, err := token.Verify(verificationKey)
		assert.NoError(b, err)
		assert.True(b, isValid)
	}
}

func TestTokenAuthV3_8_32__Parse(t *testing.T) {
	token, err := Parse("eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYzLTgtMzIiLCJjcml0IjpbImNpcmN1aXRJZCJdLCJ0eXAiOiJKV1oifQ.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjIwNDg3MDI1OTkyOTcyOTYyODc3OTY3MjQzODk1MzE1ODE3MTM3MjMzNDMzMjU4NDU2MjQ0NTE2NzQwNjEzODU2NzE4MjcwNzQwMzciLCIxOTEwNDA4NTI2MTk0MzQ0NjMxMjI0NzQzMjc4OTkxNDE1OTg3MjYwNjA0OTU5Mjk0NTc0NzU1NDgzOTU0NzA5Nzc3NDIzNDY2ODU2OCIsIjEiXSwicGlfYiI6W1siNjE2MjUzNTAxMDg3NjE5MzQzNDUwOTExNTYxOTA2MDEwMTY4OTIwNDY1NTEwNzIxNDEwMzU5OTIyNzUyNzY2ODQwMDQ5MTM3MzQxMSIsIjkyNzIxMDQ1NDM0NTE0MDM1MTc4NTAxODIxMzUwMjQ3OTM5MjY3NDc4MDMwMTg2NzgyOTA3NjA3MjEzNzYzNzQ5ODE2ODM5OTY3NDEiXSxbIjIwMjYwNDAxMTQ2NTYwMzY3MTEzOTMwODcyMjUwMjMwMjA1ODYyNDkxMzA0NDgwNzczODY1ODY5OTAzNTY3MjEzMjkwODU5MDU5NDY4IiwiOTY4MDc2NTA1MzA3NDk4NDAzNTk3NzU1NDY5MTQ2MzAwNTIwOTE0Njg0MjcwMjA5ODIxOTA1MDYyMDExNjE5NDU3OTc2MzM0NDcwNyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNzYyNzc1NDM4MzY4ODY3MDkwOTcyNzY5MzIwNjYzNzA2MjIzNjM2NzYyMDIzODQ5MTkwMDM0ODQ5MzAzNjQzODczOTMyOTgzMzM4IiwiODI2MzczODE2MjkyMzU0NTM4MzA1MTQ1MzA0MTkzNTI5MDgxMzI0NzM3MzA0NTE3NjgwNjY5Nzc5NzIwMzg3OTYzNjgwMzY2MTc0IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIzMjczMTY3OTAwNTc2NTgwODkyNzIyNjE1NjE3ODE1NDc1ODIzMzUxNTYwNzE2MDA5MDU1OTQ0Njc3NzIzMTQ0Mzk4NDQzMDA5IiwiNjgwNzU0MjkzMjczOTYyNjM1MjM3MjIwMjc0NzY1MDQ3OTQxMzM0MzI4NDg0MzcxMzE5OTkwMzg0OTA1MTgwMTAzNTQyOTA0Mjg2NSIsIjIwNzQ2OTY3OTQ5MjQyOTcwNTA0NzM1Nzc1NjgxMDI0OTI4OTg0MzEyMTk5NDA2ODkyMjgwNDM3MDUwNDk5MTAyNjA3MDY3NTI2MjM4Il19")
	assert.NoError(t, err)

	var zkProof types.ZKProof
	proofBytes, err := base64.RawURLEncoding.DecodeString("eyJwcm9vZiI6eyJwaV9hIjpbIjIwNDg3MDI1OTkyOTcyOTYyODc3OTY3MjQzODk1MzE1ODE3MTM3MjMzNDMzMjU4NDU2MjQ0NTE2NzQwNjEzODU2NzE4MjcwNzQwMzciLCIxOTEwNDA4NTI2MTk0MzQ0NjMxMjI0NzQzMjc4OTkxNDE1OTg3MjYwNjA0OTU5Mjk0NTc0NzU1NDgzOTU0NzA5Nzc3NDIzNDY2ODU2OCIsIjEiXSwicGlfYiI6W1siNjE2MjUzNTAxMDg3NjE5MzQzNDUwOTExNTYxOTA2MDEwMTY4OTIwNDY1NTEwNzIxNDEwMzU5OTIyNzUyNzY2ODQwMDQ5MTM3MzQxMSIsIjkyNzIxMDQ1NDM0NTE0MDM1MTc4NTAxODIxMzUwMjQ3OTM5MjY3NDc4MDMwMTg2NzgyOTA3NjA3MjEzNzYzNzQ5ODE2ODM5OTY3NDEiXSxbIjIwMjYwNDAxMTQ2NTYwMzY3MTEzOTMwODcyMjUwMjMwMjA1ODYyNDkxMzA0NDgwNzczODY1ODY5OTAzNTY3MjEzMjkwODU5MDU5NDY4IiwiOTY4MDc2NTA1MzA3NDk4NDAzNTk3NzU1NDY5MTQ2MzAwNTIwOTE0Njg0MjcwMjA5ODIxOTA1MDYyMDExNjE5NDU3OTc2MzM0NDcwNyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNzYyNzc1NDM4MzY4ODY3MDkwOTcyNzY5MzIwNjYzNzA2MjIzNjM2NzYyMDIzODQ5MTkwMDM0ODQ5MzAzNjQzODczOTMyOTgzMzM4IiwiODI2MzczODE2MjkyMzU0NTM4MzA1MTQ1MzA0MTkzNTI5MDgxMzI0NzM3MzA0NTE3NjgwNjY5Nzc5NzIwMzg3OTYzNjgwMzY2MTc0IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIzMjczMTY3OTAwNTc2NTgwODkyNzIyNjE1NjE3ODE1NDc1ODIzMzUxNTYwNzE2MDA5MDU1OTQ0Njc3NzIzMTQ0Mzk4NDQzMDA5IiwiNjgwNzU0MjkzMjczOTYyNjM1MjM3MjIwMjc0NzY1MDQ3OTQxMzM0MzI4NDg0MzcxMzE5OTkwMzg0OTA1MTgwMTAzNTQyOTA0Mjg2NSIsIjIwNzQ2OTY3OTQ5MjQyOTcwNTA0NzM1Nzc1NjgxMDI0OTI4OTg0MzEyMTk5NDA2ODkyMjgwNDM3MDUwNDk5MTAyNjA3MDY3NTI2MjM4Il19")
	assert.NoError(t, err)
	err = json.Unmarshal(proofBytes, &zkProof)
	assert.NoError(t, err)

	payloadBytes, err := base64.RawURLEncoding.DecodeString("bXltZXNzYWdl")
	assert.NoError(t, err)

	assert.Equal(t, zkProof.PubSignals, token.ZkProof.PubSignals)
	assert.Equal(t, zkProof.Proof, token.ZkProof.Proof)
	assert.Equal(t, "authV3-8-32", token.CircuitID)
	assert.Equal(t, "groth16", token.Alg)
	assert.Equal(t, payloadBytes, token.raw.Payload)
}

func TestTokenAuthV3_8_32__ParseWithOutputs(t *testing.T) {
	token, err := Parse("eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYzLTgtMzIiLCJjcml0IjpbImNpcmN1aXRJZCJdLCJ0eXAiOiJKV1oifQ.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjIwNDg3MDI1OTkyOTcyOTYyODc3OTY3MjQzODk1MzE1ODE3MTM3MjMzNDMzMjU4NDU2MjQ0NTE2NzQwNjEzODU2NzE4MjcwNzQwMzciLCIxOTEwNDA4NTI2MTk0MzQ0NjMxMjI0NzQzMjc4OTkxNDE1OTg3MjYwNjA0OTU5Mjk0NTc0NzU1NDgzOTU0NzA5Nzc3NDIzNDY2ODU2OCIsIjEiXSwicGlfYiI6W1siNjE2MjUzNTAxMDg3NjE5MzQzNDUwOTExNTYxOTA2MDEwMTY4OTIwNDY1NTEwNzIxNDEwMzU5OTIyNzUyNzY2ODQwMDQ5MTM3MzQxMSIsIjkyNzIxMDQ1NDM0NTE0MDM1MTc4NTAxODIxMzUwMjQ3OTM5MjY3NDc4MDMwMTg2NzgyOTA3NjA3MjEzNzYzNzQ5ODE2ODM5OTY3NDEiXSxbIjIwMjYwNDAxMTQ2NTYwMzY3MTEzOTMwODcyMjUwMjMwMjA1ODYyNDkxMzA0NDgwNzczODY1ODY5OTAzNTY3MjEzMjkwODU5MDU5NDY4IiwiOTY4MDc2NTA1MzA3NDk4NDAzNTk3NzU1NDY5MTQ2MzAwNTIwOTE0Njg0MjcwMjA5ODIxOTA1MDYyMDExNjE5NDU3OTc2MzM0NDcwNyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNzYyNzc1NDM4MzY4ODY3MDkwOTcyNzY5MzIwNjYzNzA2MjIzNjM2NzYyMDIzODQ5MTkwMDM0ODQ5MzAzNjQzODczOTMyOTgzMzM4IiwiODI2MzczODE2MjkyMzU0NTM4MzA1MTQ1MzA0MTkzNTI5MDgxMzI0NzM3MzA0NTE3NjgwNjY5Nzc5NzIwMzg3OTYzNjgwMzY2MTc0IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIzMjczMTY3OTAwNTc2NTgwODkyNzIyNjE1NjE3ODE1NDc1ODIzMzUxNTYwNzE2MDA5MDU1OTQ0Njc3NzIzMTQ0Mzk4NDQzMDA5IiwiNjgwNzU0MjkzMjczOTYyNjM1MjM3MjIwMjc0NzY1MDQ3OTQxMzM0MzI4NDg0MzcxMzE5OTkwMzg0OTA1MTgwMTAzNTQyOTA0Mjg2NSIsIjIwNzQ2OTY3OTQ5MjQyOTcwNTA0NzM1Nzc1NjgxMDI0OTI4OTg0MzEyMTk5NDA2ODkyMjgwNDM3MDUwNDk5MTAyNjA3MDY3NTI2MjM4Il19")
	assert.NoError(t, err)

	outs := circuits.AuthV3PubSignals{}
	err = token.ParsePubSignals(&outs)
	assert.NoError(t, err)

	assert.Equal(t, "wuzLSsUkkPdMn16Md8uHLKnfw9b3GB7gLLheTJfSc", outs.UserID.String())
	assert.Equal(t, "5e3463f1f0624decb3fa263df062bbf5af019e3092ed541a8bd42441235ede2d", outs.GISTRoot.Hex())

	msgHash, err := token.GetMessageHash()
	assert.NoError(t, err)
	assert.Equal(t, msgHash, outs.Challenge.Bytes())

	did, err := core.ParseDIDFromID(*outs.UserID)
	assert.NoError(t, err)
	assert.Equal(t, "did:iden3:polygon:mumbai:wuzLSsUkkPdMn16Md8uHLKnfw9b3GB7gLLheTJfSc", did.String())
}

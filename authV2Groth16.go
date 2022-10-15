package jwz

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
	"github.com/iden3/go-rapidsnark/witness"
)

const authV2Circuit string = "authV2"

// ProvingMethodGroth16AuthV2 defines proofs family and specific circuit
type ProvingMethodGroth16AuthV2 struct {
	alg       string
	circuitID string
}

// ProvingMethodGroth16AuthV2Instance instance for groth16 proving method with an authV2 circuit
var ProvingMethodGroth16AuthV2Instance *ProvingMethodGroth16AuthV2

// nolint : used for init proving method instance
func init() {
	ProvingMethodGroth16AuthV2Instance = &ProvingMethodGroth16AuthV2{alg: groth16, circuitID: authV2Circuit}
	RegisterProvingMethod(ProvingMethodGroth16AuthV2Instance.alg, func() ProvingMethod {
		return ProvingMethodGroth16AuthV2Instance
	})
}

// Alg returns current zk alg
func (m *ProvingMethodGroth16AuthV2) Alg() string {
	return m.alg
}

// CircuitID returns name of circuit
func (m *ProvingMethodGroth16AuthV2) CircuitID() string {
	return m.circuitID
}

// Verify performs groth16 proof verification and checks equality of message hash and proven challenge public signals
func (m *ProvingMethodGroth16AuthV2) Verify(messageHash []byte, proof *types.ZKProof, verificationKey []byte) error {

	var outputs circuits.AuthV2PubSignals
	pubBytes, err := json.Marshal(proof.PubSignals)
	if err != nil {
		return err
	}

	err = outputs.PubSignalsUnmarshal(pubBytes)
	if err != nil {
		return err
	}

	if outputs.Challenge.Cmp(new(big.Int).SetBytes(messageHash)) != 0 {
		return errors.New("challenge is not equal to message hash")
	}

	return verifier.VerifyGroth16(*proof, verificationKey)
}

// Prove generates proof using auth circuit and groth16 alg, checks that proven message hash is set as a part of circuit specific inputs
func (m *ProvingMethodGroth16AuthV2) Prove(inputs, provingKey, wasm []byte) (*types.ZKProof, error) {

	calc, err := witness.NewCircom2WitnessCalculator(wasm, true)
	if err != nil {
		return nil, err
	}

	parsedInputs, err := witness.ParseInputs(inputs)
	if err != nil {
		return nil, err
	}

	wtnsBytes, err := calc.CalculateWTNSBin(parsedInputs, true)
	if err != nil {
		return nil, err
	}
	return prover.Groth16Prover(provingKey, wtnsBytes)

}

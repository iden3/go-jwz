// Package jwz contains implementation of JSON WEB ZERO-Knowledge specification.
package jwz

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
	"github.com/iden3/go-rapidsnark/witness/v2"
	"github.com/iden3/go-rapidsnark/witness/wazero"
)

const (
	// Groth16 alg
	Groth16 string = "groth16"
)

// AuthGroth16Alg its first auth v1 alg (groth16 vs auth v1 circuit)
var AuthGroth16Alg = ProvingMethodAlg{Groth16, string(circuits.AuthCircuitID)}

// ProvingMethodGroth16Auth defines proofs family and specific circuit
type ProvingMethodGroth16Auth struct {
	ProvingMethodAlg
}

// ProvingMethodGroth16AuthInstance instance for Groth16 proving method with an auth circuit
var (
	ProvingMethodGroth16AuthInstance *ProvingMethodGroth16Auth
)

// nolint : used for init proving method instance
func init() {
	ProvingMethodGroth16AuthInstance = &ProvingMethodGroth16Auth{AuthGroth16Alg}
	RegisterProvingMethod(ProvingMethodGroth16AuthInstance.ProvingMethodAlg, func() ProvingMethod {
		return ProvingMethodGroth16AuthInstance
	})
}

// Alg returns current zk alg
func (m *ProvingMethodGroth16Auth) Alg() string {
	return m.ProvingMethodAlg.Alg
}

// CircuitID returns name of circuit
func (m *ProvingMethodGroth16Auth) CircuitID() string {
	return m.ProvingMethodAlg.CircuitID
}

// Verify performs Groth16 proof verification and checks equality of message hash and proven challenge public signals
func (m *ProvingMethodGroth16Auth) Verify(messageHash []byte, proof *types.ZKProof, verificationKey []byte) error {

	var outputs circuits.AuthPubSignals
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

// Prove generates proof using auth circuit and Groth16 alg, checks that proven message hash is set as a part of circuit specific inputs
func (m *ProvingMethodGroth16Auth) Prove(inputs, provingKey, wasm []byte) (*types.ZKProof, error) {
	calc, err := witness.NewCalculator(wasm,
		witness.WithWasmEngine(wazero.NewCircom2WZWitnessCalculator))
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

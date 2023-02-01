package jwz

import (
	"encoding/json"
	"errors"
	"hash/crc32"
	"math/big"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
	"github.com/iden3/go-rapidsnark/witness"
)

// AuthV2Groth16Alg its auth v2 alg (groth16 vs auth v2 circuit)
var AuthV2Groth16Alg = ProvingMethodAlg{Groth16, string(circuits.AuthV2CircuitID)}

// ProvingMethodGroth16AuthV2 instance for Groth16 proving method with an authV2 circuit
type ProvingMethodGroth16AuthV2 struct {
	ProvingMethodAlg
}

// ProvingMethodGroth16AuthInstance instance for Groth16 proving method with an authV2 circuit
var (
	ProvingMethodGroth16AuthV2Instance *ProvingMethodGroth16AuthV2
)

var authV2WasmHash uint32
var authV2WitnessCalc *witness.Circom2WitnessCalculator

// nolint : used for init proving method instance
func init() {
	ProvingMethodGroth16AuthV2Instance = &ProvingMethodGroth16AuthV2{AuthV2Groth16Alg}
	RegisterProvingMethod(ProvingMethodGroth16AuthV2Instance.ProvingMethodAlg, func() ProvingMethod {
		return ProvingMethodGroth16AuthV2Instance
	})
}

// Alg returns current zk alg
func (m *ProvingMethodGroth16AuthV2) Alg() string {
	return m.ProvingMethodAlg.Alg
}

// CircuitID returns name of circuit
func (m *ProvingMethodGroth16AuthV2) CircuitID() string {
	return m.ProvingMethodAlg.CircuitID
}

// Verify performs Groth16 proof verification and checks equality of message hash and proven challenge public signals
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

// Prove generates proof using authV2 circuit and Groth16 alg,
// checks that proven message hash is set as a part of circuit specific inputs
func (m *ProvingMethodGroth16AuthV2) Prove(inputs, provingKey, wasm []byte) (*types.ZKProof, error) {

	var calc *witness.Circom2WitnessCalculator
	var err error

	hash := crc32.ChecksumIEEE(wasm)
	if hash == authV2WasmHash {
		calc = authV2WitnessCalc
	} else {
		calc, err = witness.NewCircom2WitnessCalculator(wasm, true)
		if err != nil {
			return nil, err
		}
		authV2WitnessCalc = calc
		authV2WasmHash = hash
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

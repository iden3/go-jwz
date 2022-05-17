package jwz

import (
	"encoding/json"
	"errors"
	"fmt"
	witnesscalc "github.com/iden3/go-circom-witnesscalc"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-rapidsnark"
	"github.com/iden3/go-schema-processor/verifiable"
	"math/big"
	"time"
)

const groth16 string = "groth16"
const authCircuit string = "auth"

// ProvingMethodGroth16 defines proofs family
type ProvingMethodGroth16Auth struct {
	alg       string
	circuitID string
}

// ProvingMethodGroth16AuthInstance instance for groth16 proving method with an auth circuit
var (
	ProvingMethodGroth16AuthInstance *ProvingMethodGroth16Auth
)

func init() {
	ProvingMethodGroth16AuthInstance = &ProvingMethodGroth16Auth{alg: groth16, circuitID: authCircuit}
	RegisterProvingMethod(ProvingMethodGroth16AuthInstance.alg, func() ProvingMethod {
		return ProvingMethodGroth16AuthInstance
	})
}

// Alg returns current zk alg
func (m *ProvingMethodGroth16Auth) Alg() string {
	return m.alg
}

// CircuitID returns name of circuit
func (m *ProvingMethodGroth16Auth) CircuitID() string {
	return m.circuitID
}

// Verify performs groth16 proof verification and checks equality of message hash and proven challenge public signals
func (m *ProvingMethodGroth16Auth) Verify(messageHash []byte, proof *verifiable.ZKProof, verificationKey []byte) error {

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

	return VerifyProof(*proof, verificationKey)
}

// Prove generates proof using auth circuit and groth16 alg, checks that proven message hash is set as a part of circuit specific inputs
func (m *ProvingMethodGroth16Auth) Prove(inputs, provingKey, wasm []byte) (*verifiable.ZKProof, error) {

	now := time.Now()
	calc, err := witnesscalc.NewCircom2WitnessCalculator(wasm, true)
	if err != nil {
		return nil, err
	}

	parsedInputs, err := witnesscalc.ParseInputs(inputs)
	if err != nil {
		return nil, err
	}

	wtnsBytes, err := calc.CalculateWTNSBin(parsedInputs, true)
	if err != nil {
		return nil, err
	}
	fmt.Println(time.Since(now))
	now = time.Now()
	proof, publicInputs, err := rapidsnark.Groth16Prover(provingKey, wtnsBytes)
	if err != nil {
		return nil, err
	}
	fmt.Println(time.Since(now))

	var p verifiable.ProofData
	var ps []string

	err = json.Unmarshal([]byte(proof), &p)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal([]byte(publicInputs), &ps)
	if err != nil {
		return nil, err
	}

	return &verifiable.ZKProof{Proof: &p, PubSignals: ps}, nil
}

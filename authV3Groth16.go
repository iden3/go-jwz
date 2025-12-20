package jwz

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"sync"

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

// AuthV3Groth16Alg its auth v3 alg (groth16 vs auth v3 circuit)
var AuthV3Groth16Alg = ProvingMethodAlg{Groth16, string(circuits.AuthV3CircuitID)}

// ProvingMethodGroth16AuthV3 instance for Groth16 proving method with an authV3 circuit
type ProvingMethodGroth16AuthV3 struct {
	ProvingMethodAlg
	circuitSubVersions []string
	cacheMutex         sync.RWMutex
	cache              map[[sha256.Size]byte]witness.Calculator
}

var (
	// ProvingMethodGroth16AuthV3Instance instance for Groth16 proving method with an authV3 circuit
	ProvingMethodGroth16AuthV3Instance *ProvingMethodGroth16AuthV3
)

// nolint : used for init proving method instance
func init() {
	authV3_8_32 := "authV3-8-32"
	ProvingMethodGroth16AuthV3Instance = &ProvingMethodGroth16AuthV3{
		ProvingMethodAlg:   AuthV3Groth16Alg,
		circuitSubVersions: []string{authV3_8_32},
		cache:              make(map[[sha256.Size]byte]witness.Calculator),
	}

	RegisterProvingMethod(ProvingMethodGroth16AuthV3Instance.ProvingMethodAlg,
		func() ProvingMethod { return ProvingMethodGroth16AuthV3Instance })

	RegisterProvingMethod(ProvingMethodAlg{Groth16, authV3_8_32},
		func() ProvingMethod { return ProvingMethodGroth16AuthV3Instance })
}

// Alg returns current zk alg
func (m *ProvingMethodGroth16AuthV3) Alg() string {
	return m.ProvingMethodAlg.Alg
}

// CircuitID returns name of circuit
func (m *ProvingMethodGroth16AuthV3) CircuitID() string {
	return m.ProvingMethodAlg.CircuitID
}

// SupportedCircuits returns list of supported circuit IDs
func (m *ProvingMethodGroth16AuthV3) SupportedCircuits() []string {
	seen := make(map[string]struct{}, 1+len(m.circuitSubVersions))
	out := make([]string, 0, 1+len(m.circuitSubVersions))

	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	add(m.ProvingMethodAlg.CircuitID)
	for _, s := range m.circuitSubVersions {
		add(s)
	}
	return out
}

// Verify performs Groth16 proof verification and checks equality of message hash and proven challenge public signals
func (m *ProvingMethodGroth16AuthV3) Verify(messageHash []byte, proof *types.ZKProof, verificationKey []byte) error {

	var outputs circuits.AuthV3PubSignals
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

// Prove generates proof using authV3 circuit and Groth16 alg,
// checks that proven message hash is set as a part of circuit specific inputs
func (m *ProvingMethodGroth16AuthV3) Prove(inputs, provingKey, wasm []byte) (*types.ZKProof, error) {

	calc, err := m.newWitCalc(wasm)
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

// Instantiate new NewCircom2WZWitnessCalculator for wasm module or use cached one
func (m *ProvingMethodGroth16AuthV3) newWitCalc(
	wasm []byte) (witness.Calculator, error) {

	modID := sha256.Sum256(wasm)
	m.cacheMutex.RLock()
	witCalc, cacheHit := m.cache[modID]
	m.cacheMutex.RUnlock()

	if cacheHit {
		return witCalc, nil
	}

	witCalc, err := witness.NewCalculator(wasm,
		witness.WithWasmEngine(wazero.NewCircom2WZWitnessCalculator))
	if err != nil {
		return nil, err
	}

	var oldWitCalc witness.Calculator

	m.cacheMutex.Lock()
	oldWitCalc, cacheHit = m.cache[modID]
	if !cacheHit {
		m.cache[modID] = witCalc
	}
	m.cacheMutex.Unlock()

	if cacheHit {
		// Somebody put a witCalc in the cache while we were creating ours.
		c, ok := witCalc.(io.Closer)
		if ok {
			err = c.Close()
		}
		return oldWitCalc, err
	}

	return witCalc, nil
}

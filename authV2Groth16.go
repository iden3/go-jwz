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

// AuthV2Groth16Alg its auth v2 alg (groth16 vs auth v2 circuit)
var AuthV2Groth16Alg = ProvingMethodAlg{Groth16, string(circuits.AuthV2CircuitID)}

// ProvingMethodGroth16AuthV2 instance for Groth16 proving method with an authV2 circuit
type ProvingMethodGroth16AuthV2 struct {
	ProvingMethodAlg
	cacheMutex sync.RWMutex
	cache      map[[sha256.Size]byte]witness.Calculator
}

// ProvingMethodGroth16AuthInstance instance for Groth16 proving method with an authV2 circuit
var (
	ProvingMethodGroth16AuthV2Instance *ProvingMethodGroth16AuthV2
)

// nolint : used for init proving method instance
func init() {
	ProvingMethodGroth16AuthV2Instance = &ProvingMethodGroth16AuthV2{
		ProvingMethodAlg: AuthV2Groth16Alg,
		cache:            make(map[[sha256.Size]byte]witness.Calculator),
	}
	RegisterProvingMethod(ProvingMethodGroth16AuthV2Instance.ProvingMethodAlg,
		func() ProvingMethod { return ProvingMethodGroth16AuthV2Instance })
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

	var calc witness.Calculator
	var err error

	calc, err = m.newWitCalc(wasm)
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
func (m *ProvingMethodGroth16AuthV2) newWitCalc(
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

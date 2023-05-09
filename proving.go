package jwz

import (
	"sync"

	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-rapidsnark/types"
)

// ProvingMethodAlg defines proofs family and specific circuit
type ProvingMethodAlg struct {
	Alg       string
	CircuitID string
}

// NewProvingMethodAlg creates a new ProvingMethodAlg
func NewProvingMethodAlg(alg, circuitID string) ProvingMethodAlg {
	return ProvingMethodAlg{Alg: alg, CircuitID: circuitID}
}

var provingMethods = map[ProvingMethodAlg]func() ProvingMethod{}
var provingMethodLock = new(sync.RWMutex)

// ProvingMethod can be used add new methods for signing or verifying tokens.
type ProvingMethod interface {
	Verify(messageHash []byte, proof *types.ZKProof, verificationKey []byte) error // Returns nil if proof is valid
	Prove(inputs []byte, provingKey []byte, wasm []byte) (*types.ZKProof, error)   // Returns proof or error
	Alg() string                                                                   // Returns the alg identifier for this method (example: 'AUTH-GROTH-16')
	CircuitID() string
}

// RegisterProvingMethod registers the "alg" name and a factory function for proving method.
// This is typically done during init() in the method's implementation
func RegisterProvingMethod(alg ProvingMethodAlg, f func() ProvingMethod) {
	provingMethodLock.Lock()
	defer provingMethodLock.Unlock()
	provingMethods[alg] = f
}

// GetProvingMethod retrieves a proving method from an "alg" string
func GetProvingMethod(alg ProvingMethodAlg) (method ProvingMethod) {
	provingMethodLock.RLock()
	defer provingMethodLock.RUnlock()
	if methodF, ok := provingMethods[alg]; ok {
		method = methodF()
	}
	return
}

// GetAlgorithms returns a list of registered "alg" names
func GetAlgorithms() (algs []ProvingMethodAlg) {
	provingMethodLock.RLock()
	defer provingMethodLock.RUnlock()

	for alg := range provingMethods {
		algs = append(algs, alg)
	}
	return
}

// ProofInputsPreparerHandlerFunc prepares inputs using hash message and circuit id
type ProofInputsPreparerHandlerFunc func(hash []byte, circuitID circuits.CircuitID) ([]byte, error)

// Prepare function is responsible to call provided handler for inputs preparation
func (f ProofInputsPreparerHandlerFunc) Prepare(hash []byte, circuitID circuits.CircuitID) ([]byte, error) {
	return f(hash, circuitID)
}

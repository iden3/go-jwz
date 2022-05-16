package jwz

import (
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-schema-processor/verifiable"
	"sync"
)

var provingMethods = map[string]func() ProvingMethod{}
var provingMethodLock = new(sync.RWMutex)

// ProvingMethod can be used add new methods for signing or verifying tokens.
type ProvingMethod interface {
	Verify(messageHash []byte, proof *verifiable.ZKProof, verificationKey []byte) error // Returns nil if proof is valid
	Prove(inputs []byte, provingKey []byte, wasm []byte) (*verifiable.ZKProof, error)   // Returns proof or error
	Alg() string                                                                        // Returns the alg identifier for this method (example: 'AUTH-GROTH-16')
	CircuitID() string
}

// RegisterProvingMethod registers the "alg" name and a factory function for proving method.
// This is typically done during init() in the method's implementation
func RegisterProvingMethod(alg string, f func() ProvingMethod) {
	provingMethodLock.Lock()
	defer provingMethodLock.Unlock()
	provingMethods[alg] = f
}

// GetProvingMethod retrieves a proving method from an "alg" string
func GetProvingMethod(alg string) (method ProvingMethod) {
	provingMethodLock.RLock()
	defer provingMethodLock.RUnlock()
	if methodF, ok := provingMethods[alg]; ok {
		method = methodF()
	}
	return
}

// GetAlgorithms returns a list of registered "alg" names
func GetAlgorithms() (algs []string) {
	provingMethodLock.RLock()
	defer provingMethodLock.RUnlock()

	for alg := range provingMethods {
		algs = append(algs, alg)
	}
	return
}

type ProofInputsPreparerHandlerFunc func(hash []byte, circuitID circuits.CircuitID) ([]byte, error)

// Prepare function is responsible to call provided handler for inputs preparation
func (f ProofInputsPreparerHandlerFunc) Prepare(hash []byte, circuitID circuits.CircuitID) ([]byte, error) {
	return f(hash, circuitID)
}

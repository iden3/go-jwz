package jwz

import (
	"sync"

	"github.com/iden3/go-schema-processor/verifiable"
)

var provingMethods = map[string]func() ProvingMethod{}
var provingMethodLock = new(sync.RWMutex)

// ProvingMethod can be used add new methods for signing or verifying tokens.
type ProvingMethod interface {
	Verify(messageHash []byte, proof *verifiable.ZKProof, verificationKey interface{}) error // Returns nil if proof is valid
	Prove(messageHash []byte, inputs interface{}) (*verifiable.ZKProof, error)               // Returns proof or error
	Alg() string                                                                             // Returns the alg identifier for this method (example: 'AUTH-GROTH-16')
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

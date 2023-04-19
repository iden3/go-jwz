module github.com/iden3/go-jwz

go 1.18

//replace (
//	github.com/iden3/go-rapidsnark/prover => ../go-rapidsnark/prover
//	github.com/iden3/go-rapidsnark/types => ../go-rapidsnark/types
//	github.com/iden3/go-rapidsnark/verifier => ../go-rapidsnark/verifier
//	github.com/iden3/go-rapidsnark/witness => ../go-rapidsnark/witness
//)

require (
	github.com/iden3/go-circuits v1.0.2
	github.com/iden3/go-iden3-core v1.0.0
	github.com/iden3/go-iden3-crypto v0.0.14
	github.com/iden3/go-rapidsnark/prover v0.0.9
	github.com/iden3/go-rapidsnark/types v0.0.2
	github.com/iden3/go-rapidsnark/verifier v0.0.3
	github.com/iden3/go-rapidsnark/verifier v0.0.3
	github.com/iden3/go-rapidsnark/witness v0.0.4-0.20230417085122-1eb454a1211a
	github.com/stretchr/testify v1.8.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/ethereum/go-ethereum v1.10.26 // indirect
	github.com/iden3/go-merkletree-sql/v2 v2.0.0 // indirect
	github.com/iden3/wasmer-go v0.0.0-20230217163329-62d85068ec47 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.0.1 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

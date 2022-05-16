package jwz

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/iden3/go-rapidsnark"
	"github.com/iden3/go-schema-processor/verifiable"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"strings"
)

/*
	File proof generation. it will be deleted
*/

// GenerateZkProof executes snarkjs groth16prove function and returns proof only if it's valid
func GenerateZkProof(inputs, provingKey, wasm []byte) (*verifiable.ZKProof, error) {

	dir := "/tmp/"

	// create tmf file for inputs
	inputFile, err := ioutil.TempFile(dir, "input-*.json")
	if err != nil {
		return nil, errors.New("failed to create tmf file for inputs")
	}
	defer os.Remove(inputFile.Name())

	// write json inputs into tmp file
	_, err = inputFile.Write(inputs)
	if err != nil {
		return nil, errors.New("failed to write json inputs into tmp file")
	}
	err = inputFile.Close()
	if err != nil {
		return nil, err
	}

	// create tmf wasm for wasm
	wasmFile, err := ioutil.TempFile(dir, "wasm-*.wasm")
	if err != nil {
		return nil, errors.New("failed to create tmf file for inputs")
	}
	defer os.Remove(wasmFile.Name())

	// write json inputs into tmp file
	_, err = wasmFile.Write(wasm)
	if err != nil {
		return nil, errors.New("failed to write wasm into tmp file")
	}
	err = wasmFile.Close()
	if err != nil {
		return nil, err
	}

	// create tmp witness file
	wtnsFile, err := ioutil.TempFile(dir, "witness-*.wtns")
	if err != nil {
		return nil, err
	}
	defer os.Remove(wtnsFile.Name())
	err = wtnsFile.Close()
	if err != nil {
		return nil, err
	}

	// calculate witness
	wtnsCmd := exec.Command("node", dir+"generate_witness.js", wasmFile.Name(), inputFile.Name(), wtnsFile.Name())
	res, err := wtnsCmd.CombinedOutput()
	if err != nil {
		fmt.Println(string(res))
		return nil, err
	}
	fmt.Println(res)

	// create tmp proof file
	proofFile, err := ioutil.TempFile(dir, "proof-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(proofFile.Name())
	err = proofFile.Close()
	if err != nil {
		return nil, err
	}

	// create tmp public file
	publicFile, err := ioutil.TempFile(dir, "public-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(publicFile.Name())
	err = publicFile.Close()
	if err != nil {
		return nil, err
	}

	// create tmf file for zkey
	keyFile, err := ioutil.TempFile(dir, "key-*.zkey")
	if err != nil {
		return nil, errors.New("failed to create tmf file for inputs")
	}
	defer os.Remove(keyFile.Name())

	// write json inputs into tmp file
	_, err = keyFile.Write(provingKey)
	if err != nil {
		return nil, errors.New("failed to write json inputs into tmp file")
	}
	err = keyFile.Close()
	if err != nil {
		return nil, err
	}

	wtnsBytes, err := ioutil.ReadFile(wtnsFile.Name())
	if err != nil {
		return nil, err
	}
	proof, publicInputs, err := rapidsnark.Groth16Prover(provingKey, wtnsBytes)
	if err != nil {
		return nil, err
	}

	var execCommandParams []string
	execCommandName := "snarkjs"
	execCommandParams = append(execCommandParams, "groth16", "prove")
	execCommandParams = append(execCommandParams, keyFile.Name(), wtnsFile.Name(), proofFile.Name(), publicFile.Name())
	proveCmd := exec.Command(execCommandName, execCommandParams...)
	_, err = proveCmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	fmt.Println("-- groth16 prove completed --")

	var p verifiable.ProofData
	var ps []string

	// read generated public signals
	//publicJSON, err := os.ReadFile(publicFile.Name())
	//if err != nil {
	//	return nil, err
	//}
	//
	//err = json.Unmarshal(publicJSON, &pubSignals)
	//if err != nil {
	//	return nil, err
	//}
	//// read generated proof
	//proofJSON, err := os.ReadFile(proofFile.Name())
	//if err != nil {
	//	return nil, err
	//}

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

// r is the mod of the finite field
const r string = "21888242871839275222246405745257275088548364400416034343698204186575808495617"

// proofPairingData describes three components of zkp proof in bn256 format.
type proofPairingData struct {
	A *bn256.G1
	B *bn256.G2
	C *bn256.G1
}

// vk is the Verification Key data structure in bn256 format.
type vk struct {
	Alpha *bn256.G1
	Beta  *bn256.G2
	Gamma *bn256.G2
	Delta *bn256.G2
	IC    []*bn256.G1
}

// vkJSON is the Verification Key data structure in string format (from json).
type vkJSON struct {
	Alpha []string   `json:"vk_alpha_1"`
	Beta  [][]string `json:"vk_beta_2"`
	Gamma [][]string `json:"vk_gamma_2"`
	Delta [][]string `json:"vk_delta_2"`
	IC    [][]string `json:"IC"`
}

// VerifyProof performs a verification of zkp  based on verification key and public inputs
func VerifyProof(zkProof verifiable.ZKProof, verificationKey []byte) error {

	// 1. cast external proof data to internal model.
	p, err := parseProofData(*zkProof.Proof)
	if err != nil {
		return err
	}

	// 2. cast external verification key data to internal model.
	var vkStr vkJSON
	err = json.Unmarshal(verificationKey, &vkStr)
	if err != nil {
		return err
	}
	vkKey, err := parseVK(vkStr)
	if err != nil {
		return err
	}

	// 2. cast external public inputs data to internal model.
	pubSignals, err := stringsToArrayBigInt(zkProof.PubSignals)
	if err != nil {
		return err
	}

	return verifyGroth16(vkKey, p, pubSignals)
}

// verifyGroth16 performs the verification the Groth16 zkSNARK proofs
func verifyGroth16(vk *vk, proof proofPairingData, inputs []*big.Int) error {
	if len(inputs)+1 != len(vk.IC) {
		return fmt.Errorf("len(inputs)+1 != len(vk.IC)")
	}
	vkX := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i := 0; i < len(inputs); i++ {
		// check input inside field
		v, _ := new(big.Int).SetString(r, 10)
		if inputs[i].Cmp(v) != -1 {
			return fmt.Errorf("input value is not in the fields")
		}
		vkX = new(bn256.G1).Add(vkX, new(bn256.G1).ScalarMult(vk.IC[i+1], inputs[i]))
	}
	vkX = new(bn256.G1).Add(vkX, vk.IC[0])

	g1 := []*bn256.G1{proof.A, new(bn256.G1).Neg(vk.Alpha), vkX.Neg(vkX), new(bn256.G1).Neg(proof.C)}
	g2 := []*bn256.G2{proof.B, vk.Beta, vk.Gamma, vk.Delta}

	res := bn256.PairingCheck(g1, g2)
	if !res {
		return fmt.Errorf("invalid proofs")
	}
	return nil
}

func parseProofData(pr verifiable.ProofData) (proofPairingData, error) {
	var (
		p   proofPairingData
		err error
	)

	p.A, err = stringToG1(pr.A)
	if err != nil {
		return p, err
	}

	p.B, err = stringToG2(pr.B)
	if err != nil {
		return p, err
	}

	p.C, err = stringToG1(pr.C)
	if err != nil {
		return p, err
	}

	return p, err
}

func parseVK(vkStr vkJSON) (*vk, error) {
	var v vk
	var err error
	v.Alpha, err = stringToG1(vkStr.Alpha)
	if err != nil {
		return nil, err
	}

	v.Beta, err = stringToG2(vkStr.Beta)
	if err != nil {
		return nil, err
	}

	v.Gamma, err = stringToG2(vkStr.Gamma)
	if err != nil {
		return nil, err
	}

	v.Delta, err = stringToG2(vkStr.Delta)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(vkStr.IC); i++ {
		p, err := stringToG1(vkStr.IC[i])
		if err != nil {
			return nil, err
		}
		v.IC = append(v.IC, p)
	}

	return &v, nil
}
func stringsToArrayBigInt(publicInputs []string) ([]*big.Int, error) {
	p := make([]*big.Int, 0, len(publicInputs))
	for _, s := range publicInputs {
		sb, err := stringToBigInt(s)
		if err != nil {
			return nil, err
		}
		p = append(p, sb)
	}
	return p, nil
}
func stringToBigInt(s string) (*big.Int, error) {
	base := 10
	if bytes.HasPrefix([]byte(s), []byte("0x")) {
		base = 16
		s = strings.TrimPrefix(s, "0x")
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, fmt.Errorf("can not parse string to *big.Int: %s", s)
	}
	return n, nil
}
func stringToG1(h []string) (*bn256.G1, error) {
	if len(h) <= 2 {
		return nil, fmt.Errorf("not enought data for stringToG1")
	}
	h = h[:2]
	hexa := false
	if len(h[0]) > 1 {
		if h[0][:2] == "0x" {
			hexa = true
		}
	}
	in := ""

	var b []byte
	var err error
	if hexa {
		for i := range h {
			in += strings.TrimPrefix(h[i], "0x")
		}
		b, err = hex.DecodeString(in)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO TMP
		// TODO use stringToBytes()
		if h[0] == "1" {
			h[0] = "0"
		}
		if h[1] == "1" {
			h[1] = "0"
		}
		bi0, ok := new(big.Int).SetString(h[0], 10)
		if !ok {
			return nil, fmt.Errorf("error parsing stringToG1")
		}
		bi1, ok := new(big.Int).SetString(h[1], 10)
		if !ok {
			return nil, fmt.Errorf("error parsing stringToG1")
		}
		b0 := bi0.Bytes()
		b1 := bi1.Bytes()
		if len(b0) != 32 {
			b0 = addZPadding(b0)
		}
		if len(b1) != 32 {
			b1 = addZPadding(b1)
		}

		b = append(b, b0...)
		b = append(b, b1...)
	}
	p := new(bn256.G1)
	_, err = p.Unmarshal(b)

	return p, err
}
func stringToG2(h [][]string) (*bn256.G2, error) {
	if len(h) <= 2 {
		return nil, fmt.Errorf("not enought data for stringToG2")
	}
	h = h[:2]
	hexa := false
	if len(h[0][0]) > 1 {
		if h[0][0][:2] == "0x" {
			hexa = true
		}
	}
	in := ""
	var (
		b   []byte
		err error
	)
	if hexa {
		for i := 0; i < len(h); i++ {
			for j := 0; j < len(h[i]); j++ {
				in += strings.TrimPrefix(h[i][j], "0x")
			}
		}
		b, err = hex.DecodeString(in)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO TMP
		var bH []byte
		bH, err = stringToBytes(h[0][1])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[0][0])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[1][1])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
		bH, err = stringToBytes(h[1][0])
		if err != nil {
			return nil, err
		}
		b = append(b, bH...)
	}

	p := new(bn256.G2)
	_, err = p.Unmarshal(b)
	return p, err
}
func addZPadding(b []byte) []byte {
	var z [32]byte
	var r []byte
	r = append(r, z[len(b):]...) // add padding on the left
	r = append(r, b...)
	return r[:32]
}
func stringToBytes(s string) ([]byte, error) {
	if s == "1" {
		s = "0"
	}
	bi, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("error parsing bigint stringToBytes")
	}
	b := bi.Bytes()
	if len(b) != 32 {
		b = addZPadding(b)
	}
	return b, nil

}

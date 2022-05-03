package jwz

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-schema-processor/verifiable"
	"strings"
)

type HeaderKey string

const (
	headerCritical  HeaderKey = "crit"
	headerAlg       HeaderKey = "alg"
	headerCircuitID HeaderKey = "circuitId"
	headerTyp       HeaderKey = "typ"
)

// Token represents a JWZ Token.
type Token struct {
	ZkProof *verifiable.ZKProof // The third segment of the token.  Populated when you Parse a token

	Alg       string // fields that are part of headers
	CircuitID string // id of circuit that will be used for proving

	Method ProvingMethod // proving method to create a zkp
	Valid  bool          //  shows if proof is valid. Populated after verification

	raw rawJSONWebZeroknowledge // The raw token.  Populated when you Parse a token
}

// NewWithPayload creates a new Token with the specified signing method and claims.
func NewWithPayload(prover ProvingMethod, payload []byte) (*Token, error) {

	token := &Token{
		Alg:       prover.Alg(),
		CircuitID: prover.CircuitID(),
		Method:    prover,
	}
	err := token.setHeader(prover.Alg(), prover.CircuitID())
	if err != nil {
		return nil, err
	}
	token.setPayload(payload)

	return token, nil
}

// rawJSONWebZeroknowledge is json web token with signature presented by zero knowledge proof
type rawJSONWebZeroknowledge struct {
	Payload   []byte                    `json:"payload,omitempty"`
	Protected []byte                    `json:"protected,omitempty"`
	Header    map[HeaderKey]interface{} `json:"header,omitempty"`
	ZKP       []byte                    `json:"zkp,omitempty"`
}

// SetHeader set headers for jwz
func (token *Token) setHeader(zkpAlg, circuitId string) error {
	headers := map[HeaderKey]interface{}{
		headerAlg:       zkpAlg,
		headerCritical:  []HeaderKey{headerCircuitID},
		headerCircuitID: circuitId,
		headerTyp:       "JWZ",
	}

	token.raw.Header = headers
	return nil
}
func (token *Token) setPayload(payload []byte) {
	token.raw.Payload = payload
}

func (token *Token) FullSerialize() (string, error) {

	rawBytes, err := json.Marshal(token.raw)
	return string(rawBytes), err
}
func (token *Token) CompactSerialize() (string, error) {

	if token.raw.Header == nil || token.raw.Protected == nil || token.ZkProof == nil {
		return "", errors.New("iden3/jwz:can't serialize without one of components")
	}
	serializedProtected := base64.RawURLEncoding.EncodeToString(token.raw.Protected)
	proofBytes, err := json.Marshal(token.ZkProof)
	if err != nil {
		return "", err
	}
	serializedProof := base64.RawURLEncoding.EncodeToString(proofBytes)
	serializedPayload := base64.RawURLEncoding.EncodeToString(token.raw.Payload)

	return fmt.Sprintf("%s.%s.%s", serializedProtected, serializedPayload, serializedProof), nil
}

type MapProofOutputs map[string]interface{}

func (m *MapProofOutputs) PubSignalsUnmarshal(data []byte) error {
	return json.Unmarshal(data, m)
}

// Parse parses a jwz message in compact or full serialization format with unmarhslling outputs to map
func Parse(token string) (*Token, error) {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(token, "{") {
		return parseFull(token)
	}
	return parseCompact(token)
}

//// ParseWithProofOutputs parses a jwz message in compact or full serialization format with unmarshalling to provided outputs
//func ParseWithProofOutputs(token string, out circuits.PubSignalsUnmarshaller) (t *Token, err error) {
//
//	return
//}

// ParsePubSignals
func (token *Token) ParsePubSignals(out circuits.PubSignalsUnmarshaller) error {
	marshaledPubSignals, err := json.Marshal(token.ZkProof.PubSignals)
	if err != nil {
		return err
	}

	err = out.PubSignalsUnmarshal(marshaledPubSignals)
	if err != nil {
		return err
	}
	return err
}

// ToString  Returns string representation of JWZ token
func (token *Token) ToString() string {
	header := base64.RawURLEncoding.EncodeToString(token.raw.Protected)
	payload := base64.RawURLEncoding.EncodeToString(token.raw.Payload)
	proof := base64.RawURLEncoding.EncodeToString(token.raw.ZKP)

	return fmt.Sprintf("%s.%s.%s", header, payload, proof)
}

// parseFull parses a message in full format.
func parseFull(input string) (*Token, error) {
	var parsed rawJSONWebZeroknowledge
	err := json.Unmarshal([]byte(input), &parsed)
	if err != nil {
		return nil, err
	}

	return parsed.sanitized()
}

// parseCompact parses a message in compact format.
func parseCompact(input string) (*Token, error) {
	parts := strings.Split(input, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("iden3/go-jwz: compact JWZ format must have three segments")
	}

	rawProtected, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])

	proof, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	raw := &rawJSONWebZeroknowledge{
		Payload:   rawPayload,
		Protected: rawProtected,
		ZKP:       proof,
	}
	return raw.sanitized()
}

// sanitized produces a cleaned-up JWZ object from the raw JSON.
func (parsed *rawJSONWebZeroknowledge) sanitized() (*Token, error) {
	if parsed.Payload == nil {
		return nil, fmt.Errorf("iden3/go-jwz: missing payload in JWZ message")
	}

	token := &Token{
		raw: *parsed,
	}

	var headers map[HeaderKey]interface{}

	// all headers are protected
	err := json.Unmarshal(parsed.Protected, &headers)
	if err != nil {
		return nil, err
	}
	// verify that all critical headers are presented

	criticialHeaders := headers[headerCritical].([]interface{})
	for _, key := range criticialHeaders {
		if _, ok := headers[HeaderKey(key.(string))]; !ok {
			return nil, fmt.Errorf("iden3/go-jwz: header is listed in critical %v, but not presented", key)
		}
	}

	token.raw.Header = headers

	token.Alg = headers[headerAlg].(string)
	token.CircuitID = headers[headerCircuitID].(string)
	token.Method = GetProvingMethod(token.Alg)

	// parse proof

	if len(parsed.ZKP) != 0 {
		err := json.Unmarshal(parsed.ZKP, &token.ZkProof)
		if err != nil {
			return nil, err
		}

		//marshaledPubSignals, err := json.Marshal(token.ZkProof.PubSignals)
		//if err != nil {
		//	return nil, err
		//}
		//
		//outAsMap, err := circuits.UnmarshalCircuitOutput(circuits.CircuitID(token.circuitId), b)
		//if err != nil {
		//	return nil, err
		//}
		//outAsBytes, err := json.Marshal(outAsMap)
		//if err != nil {
		//	return nil, err
		//}

		//var authPubSignals circuits.AuthPubSignals
		//err = token.Method.Output().PubSignalsUnmarshal(marshaledPubSignals)
		//if err != nil {
		//	return nil, err
		//}
		//token.id = authPubSignals.UserID
		//token.userState = authPubSignals.UserState.BigInt().String()
		//token.challenge = authPubSignals.Challenge

	}

	return token, nil
}

// Prove creates and returns a complete, prooved JWZ.
// The token is proven using the Proving Method specified in the token.
func (token *Token) Prove(inputs interface{}, provingKey interface{}) error {

	// all headers must be protected
	headers, err := json.Marshal(token.raw.Header)
	if err != nil {
		return err
	}
	token.raw.Protected = headers

	hash, err := token.GetMessageHash()
	if err != nil {
		return err
	}

	proof, err := token.Method.Prove(hash, inputs, provingKey)
	if err != nil {
		return err
	}
	token.ZkProof = proof
	return nil
}

func (token *Token) GetMessageHash() ([]byte, error) {

	headers, err := json.Marshal(token.raw.Header)
	if err != nil {
		return nil, err
	}
	protectedHeaders := base64.RawURLEncoding.EncodeToString(headers)
	payload := base64.RawURLEncoding.EncodeToString(token.raw.Payload)

	// JWZ ZkProof input value is ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)).
	messageToProof := []byte(fmt.Sprintf("%s.%s", protectedHeaders, payload))
	hash, err := PrepareMessageHash(messageToProof)

	if err != nil {
		return nil, err
	}
	return hash.Bytes(), nil
}

func (token *Token) Verify(verificationKey []byte) error {

	// 1. verify that challenge is a hash of payload message // TODO: add protected headers.

	msgHash, err := token.GetMessageHash()

	// 2. verify that zkp is valid
	err = token.Method.Verify(msgHash, token.ZkProof, verificationKey)
	if err != nil {
		return err
	}
	token.Valid = true
	return nil
}

package protocol

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// PayeeData is the data that the payer wants to know about the payee. It can be any json data.
type PayeeData map[string]interface{}

func (p *PayeeData) Compliance() (*CompliancePayeeData, error) {
	if p == nil {
		return nil, nil
	}
	if compliance, ok := (*p)["compliance"]; ok {
		if complianceMap, ok := compliance.(map[string]interface{}); ok {
			complianceJson, err := json.Marshal(complianceMap)
			if err != nil {
				return nil, err
			}
			var complianceData CompliancePayeeData
			err = json.Unmarshal(complianceJson, &complianceData)
			if err != nil {
				return nil, err
			}
			return &complianceData, nil
		}
	}
	return nil, nil
}

type CompliancePayeeData struct {
	// NodePubKey is the public key of the receiver's node if known.
	NodePubKey *string `json:"nodePubKey,omitempty"`
	// Utxos is a list of UTXOs of channels over which the receiver will likely receive the payment.
	Utxos []string `json:"utxos"`
	// UtxoCallback is the URL that the sender VASP will call to send UTXOs of the channel that the sender used to send the payment once it completes.
	UtxoCallback *string `json:"utxoCallback,omitempty"`
	// Signature is the base64-encoded signature of sha256(SenderAddress|ReceiverAddress|Nonce|Timestamp).
	// Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
	Signature *string `json:"signature,omitempty"`
	// SignatureNonce is a random string that is used to prevent replay attacks.
	// Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
	SignatureNonce *string `json:"signatureNonce,omitempty"`
	// SignatureTimestamp is the unix timestamp (in seconds since epoch) of when the request was sent. Used in the signature.
	// Note: This field is optional for UMA v0.X backwards-compatibility. It is required for UMA v1.X.
	SignatureTimestamp *int64 `json:"signatureTimestamp,omitempty"`
}

func (c *CompliancePayeeData) AsMap() (map[string]interface{}, error) {
	complianceJson, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var complianceMap map[string]interface{}
	err = json.Unmarshal(complianceJson, &complianceMap)
	if err != nil {
		return nil, err
	}
	return complianceMap, nil
}

func (c *CompliancePayeeData) SignablePayload(payerIdentifier string, payeeIdentifier string) ([]byte, error) {
	if c == nil {
		return nil, errors.New("compliance data is missing")
	}
	if c.SignatureNonce == nil || c.SignatureTimestamp == nil {
		return nil, errors.New("compliance data is missing signature nonce or timestamp. Is this a v0.X response")
	}
	payloadString := strings.Join([]string{
		payerIdentifier,
		payeeIdentifier,
		*c.SignatureNonce,
		strconv.FormatInt(*c.SignatureTimestamp, 10),
	}, "|")
	return []byte(payloadString), nil
}

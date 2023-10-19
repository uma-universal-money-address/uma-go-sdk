package uma

import (
	"encoding/json"
	"fmt"
	"strings"
)

type PayerDataOptions struct {
	NameRequired       bool
	EmailRequired      bool
	ComplianceRequired bool
}

func (p *PayerDataOptions) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{
		"identifier": { "mandatory": true },
		"name": { "mandatory": %t },
		"email": { "mandatory": %t },
		"compliance": { "mandatory": %t }
	}`, p.NameRequired, p.EmailRequired, p.ComplianceRequired)), nil
}

func decodePayerDataOptionField(data map[string]interface{}, fieldName string) bool {
	m, ok := data[fieldName].(map[string]interface{})
	if !ok {
		return false
	}
	mandatory, ok := m["mandatory"].(bool)
	if !ok {
		return false
	}
	return mandatory
}

func (p *PayerDataOptions) UnmarshalJSON(data []byte) error {
	var m map[string]interface{}
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	p.NameRequired = decodePayerDataOptionField(m, "name")
	p.EmailRequired = decodePayerDataOptionField(m, "email")
	p.ComplianceRequired = decodePayerDataOptionField(m, "compliance")

	return nil
}

type PayerData struct {
	Name       *string              `json:"name"`
	Email      *string              `json:"email"`
	Identifier string               `json:"identifier"`
	Compliance *CompliancePayerData `json:"compliance"`
}

type TravelRuleFormat struct {
	// Type is the type of the travel rule format (e.g. IVMS).
	Type string
	// Version is the version of the travel rule format (e.g. 1.0).
	Version *string
}

func (t *TravelRuleFormat) MarshalJSON() ([]byte, error) {
	if t.Version == nil {
		return []byte(t.Type), nil
	}
	return []byte(fmt.Sprintf(`%q@%q`, t.Type, &t.Version)), nil
}

func (t *TravelRuleFormat) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	if !strings.Contains(s, "@") {
		t.Type = s
		return nil
	}

	parts := strings.Split(s, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid travel rule format: %s", s)
	}

	t.Type = parts[0]
	t.Version = &parts[1]

	return nil
}

type CompliancePayerData struct {
	// Utxos is the list of UTXOs of the sender's channels that might be used to fund the payment.
	Utxos *[]string `json:"utxos"`
	// NodePubKey is the public key of the sender's node if known.
	NodePubKey *string `json:"nodePubKey"`
	// KycStatus indicates whether VASP1 has KYC information about the sender.
	KycStatus KycStatus `json:"kycStatus"`
	// EncryptedTravelRuleInfo is the travel rule information of the sender. This is encrypted with the receiver's public encryption key.
	EncryptedTravelRuleInfo *string `json:"encryptedTravelRuleInfo"`
	// TravelRuleFormat is an optional standardized format of the travel rule information (e.g. IVMS). Null indicates raw json or a custom format.
	TravelRuleFormat *TravelRuleFormat `json:"travelRuleFormat"`
	// Signature is the base64-encoded signature of sha256(ReceiverAddress|Nonce|Timestamp).
	Signature          string `json:"signature"`
	SignatureNonce     string `json:"signatureNonce"`
	SignatureTimestamp int64  `json:"signatureTimestamp"`
	// UtxoCallback is the URL that the receiver will call to send UTXOs of the channel that the receiver used to receive the payment once it completes.
	UtxoCallback string `json:"utxoCallback"`
}

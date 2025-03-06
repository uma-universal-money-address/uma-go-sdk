package protocol

import (
	"encoding/json"
	"fmt"
	"strings"
)

type PayerData map[string]interface{}

func (p *PayerData) Compliance() (*CompliancePayerData, error) {
	if p == nil {
		return nil, nil
	}
	if compliance, ok := (*p)["compliance"]; ok {
		if complianceMap, ok := compliance.(map[string]interface{}); ok {
			complianceJson, err := json.Marshal(complianceMap)
			if err != nil {
				return nil, err
			}
			var complianceData CompliancePayerData
			err = json.Unmarshal(complianceJson, &complianceData)
			if err != nil {
				return nil, err
			}
			return &complianceData, nil
		}
	}
	return nil, nil
}

func (p *PayerData) stringField(field string) *string {
	if p == nil {
		return nil
	}
	if value, ok := (*p)[field]; ok {
		if stringValue, ok := value.(string); ok {
			return &stringValue
		}
	}
	return nil
}

func (p *PayerData) Identifier() *string {
	return p.stringField("identifier")
}

func (p *PayerData) Name() *string {
	return p.stringField("name")
}

func (p *PayerData) Email() *string {
	return p.stringField("email")
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
	return []byte(fmt.Sprintf("\"%s@%s\"", t.Type, *t.Version)), nil
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
	Utxos *[]string `json:"utxos,omitempty"`
	// NodePubKey is the public key of the sender's node if known.
	NodePubKey *string `json:"nodePubKey,omitempty"`
	// KycStatus indicates whether VASP1 has KYC information about the sender.
	KycStatus KycStatus `json:"kycStatus"`
	// EncryptedTravelRuleInfo is the travel rule information of the sender. This is encrypted with the receiver's public encryption key.
	EncryptedTravelRuleInfo *string `json:"encryptedTravelRuleInfo,omitempty"`
	// TravelRuleFormat is an optional standardized format of the travel rule information (e.g. IVMS). Null indicates raw json or a custom format.
	TravelRuleFormat *TravelRuleFormat `json:"travelRuleFormat,omitempty"`
	// Signature is the base64-encoded signature of sha256(ReceiverAddress|Nonce|Timestamp).
	Signature          string `json:"signature"`
	SignatureNonce     string `json:"signatureNonce"`
	SignatureTimestamp int64  `json:"signatureTimestamp"`
	// UtxoCallback is the URL that the receiver will call to send UTXOs of the channel that the receiver used to receive the payment once it completes.
	UtxoCallback string `json:"utxoCallback"`
}

func (c *CompliancePayerData) AsMap() (map[string]interface{}, error) {
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

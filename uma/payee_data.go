package uma

import "encoding/json"

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
	// KycStatus indicates whether VASP2 has KYC information about the receiver.
	KycStatus KycStatus `json:"kycStatus"`
	// NodePubKey is the public key of the receiver's node if known.
	NodePubKey *string `json:"nodePubKey"`
	// Utxos is a list of UTXOs of channels over which the receiver will likely receive the payment.
	Utxos []string `json:"utxos"`
	// UtxoCallback is the URL that the sender VASP will call to send UTXOs of the channel that the sender used to send the payment once it completes.
	UtxoCallback string `json:"utxoCallback"`
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

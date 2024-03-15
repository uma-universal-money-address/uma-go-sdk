package protocol

type CounterPartyDataOption struct {
	Mandatory bool `json:"mandatory"`
}

// CounterPartyDataOptions describes which fields a vasp needs to know about the sender or receiver. Used for payerData
// and payeeData.
type CounterPartyDataOptions map[string]CounterPartyDataOption

type CounterPartyDataField string

const (
	CounterPartyDataFieldIdentifier    CounterPartyDataField = "identifier"
	CounterPartyDataFieldName          CounterPartyDataField = "name"
	CounterPartyDataFieldEmail         CounterPartyDataField = "email"
	CounterPartyDataFieldCountryCode   CounterPartyDataField = "countryCode"
	CounterPartyDataFieldCompliance    CounterPartyDataField = "compliance"
	CounterPartyDataFieldAccountNumber CounterPartyDataField = "accountNumber"
)

func (c CounterPartyDataField) String() string {
	return string(c)
}

package uma

type CounterPartyDataOption struct {
	Mandatory bool `json:"mandatory"`
}

// PayeeDataOptions describes which fields the payer wants to know about the payee.
type PayeeDataOptions map[string]CounterPartyDataOption

// PayeeData is the data that the payer wants to know about the payee. It can be any json data.
type PayeeData map[string]interface{}

type PayeeDataField string

const (
	PayeeDataFieldIdentifier    PayeeDataField = "identifier"
	PayeeDataFieldName          PayeeDataField = "name"
	PayeeDataFieldEmail         PayeeDataField = "email"
	PayeeDataFieldCountryCode   PayeeDataField = "countryCode"
	PayeeDataFieldAccountNumber PayeeDataField = "accountNumber"
)

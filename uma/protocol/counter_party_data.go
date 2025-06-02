package protocol

import (
	"fmt"
	"sort"
	"strings"
)

type CounterPartyDataOption struct {
	Mandatory bool `json:"mandatory"`
}

// CounterPartyDataOptions describes which fields a vasp needs to know about the sender or receiver. Used for payerData
// and payeeData.
type CounterPartyDataOptions map[string]CounterPartyDataOption

type CounterPartyDataField string

const (
	// The UMA address of the counterparty
	CounterPartyDataFieldIdentifier CounterPartyDataField = "identifier"

	// The full name of the counterparty
	CounterPartyDataFieldName CounterPartyDataField = "name"

	// The email address of the counterparty
	CounterPartyDataFieldEmail CounterPartyDataField = "email"

	// The country code of the counterparty, in ISO 3166-1 alpha-2 format
	CounterPartyDataFieldCountryCode CounterPartyDataField = "countryCode"

	// Compliance-related data including KYC status, UTXOs, and travel rule information
	CounterPartyDataFieldCompliance CounterPartyDataField = "compliance"

	// The account number of the counterparty
	CounterPartyDataFieldAccountNumber CounterPartyDataField = "accountNumber"

	// The counterparty's date of birth, in ISO 8601 format
	CounterPartyDataFieldBirthDate CounterPartyDataField = "birthDate"

	// The counterparty's nationality, in ISO 3166-1 alpha-2 format
	CounterPartyDataFieldNationality CounterPartyDataField = "nationality"
)

func (c CounterPartyDataField) String() string {
	return string(c)
}

func (c *CounterPartyDataOptions) MarshalBytes() ([]byte, error) {
	pairs := make([]string, 0, len(*c))
	for k, v := range *c {
		str := k + ":"
		if v.Mandatory {
			str += "1"
		} else {
			str += "0"
		}
		pairs = append(pairs, str)
	}

	sort.Strings(pairs)

	result := []byte(strings.Join(pairs, ","))
	return result, nil
}

func (c *CounterPartyDataOptions) UnmarshalBytes(data []byte) error {
	*c = make(CounterPartyDataOptions)
	pairs := strings.Split(string(data), ",")
	for _, pair := range pairs {
		parts := strings.Split(pair, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid pair: %s", pair)
		}
		(*c)[parts[0]] = CounterPartyDataOption{
			Mandatory: parts[1] == "1",
		}
	}
	return nil
}

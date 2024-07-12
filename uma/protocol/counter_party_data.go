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

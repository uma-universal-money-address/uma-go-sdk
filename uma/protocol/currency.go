package protocol

import "encoding/json"

type Currency struct {
	// Code is the ISO 4217 (if applicable) currency code (eg. "USD"). For cryptocurrencies, this will  be a ticker
	// symbol, such as BTC for Bitcoin.
	Code string `json:"code"`

	// Name is the full display name of the currency (eg. US Dollars).
	Name string `json:"name"`

	// Symbol is the symbol of the currency (eg. $ for USD).
	Symbol string `json:"symbol"`

	// MillisatoshiPerUnit is the estimated millisats per smallest "unit" of this currency (eg. 1 cent in USD).
	MillisatoshiPerUnit float64 `json:"multiplier"`

	// Convertible is a struct which contains the range of amounts that can be sent in a single transaction.
	Convertible ConvertibleCurrency `json:"convertible"`

	// Decimals is the number of digits after the decimal point for display on the sender side, and to add clarity
	// around what the "smallest unit" of the currency is. For example, in USD, by convention, there are 2 digits for
	// cents - $5.95. In this case, `decimals` would be 2. Note that the multiplier is still always in the smallest
	// unit (cents). In addition to display purposes, this field can be used to resolve ambiguity in what the multiplier
	// means. For example, if the currency is "BTC" and the multiplier is 1000, really we're exchanging in SATs, so
	// `decimals` would be 8.
	// For details on edge cases and examples, see https://github.com/uma-universal-money-address/protocol/blob/main/umad-04-lnurlp-response.md.
	Decimals int `json:"decimals"`

	// UmaMajorVersion is the major version of the UMA protocol that the VASP supports for this currency. This is used
	// for serialization, but is not serialized itself.
	UmaMajorVersion int `json:"-"`
}

type ConvertibleCurrency struct {
	// MinSendable is the minimum amount of the currency that can be sent in a single transaction. This is in the
	// smallest unit of the currency (eg. cents for USD).
	MinSendable int64 `json:"min"`

	// MaxSendable is the maximum amount of the currency that can be sent in a single transaction. This is in the
	// smallest unit of the currency (eg. cents for USD).
	MaxSendable int64 `json:"max"`
}

type v0Currency struct {
	Code                string  `json:"code"`
	Name                string  `json:"name"`
	Symbol              string  `json:"symbol"`
	MillisatoshiPerUnit float64 `json:"multiplier"`
	MinSendable         int64   `json:"minSendable"`
	MaxSendable         int64   `json:"maxSendable"`
	Decimals            int     `json:"decimals"`
}

type v1Currency struct {
	Code                string              `json:"code"`
	Name                string              `json:"name"`
	Symbol              string              `json:"symbol"`
	MillisatoshiPerUnit float64             `json:"multiplier"`
	Convertible         ConvertibleCurrency `json:"convertible"`
	Decimals            int                 `json:"decimals"`
}

func (c *Currency) MarshalJSON() ([]byte, error) {
	if c.UmaMajorVersion == 0 {
		return json.Marshal(&v0Currency{
			Code:                c.Code,
			Name:                c.Name,
			Symbol:              c.Symbol,
			MillisatoshiPerUnit: c.MillisatoshiPerUnit,
			MinSendable:         c.Convertible.MinSendable,
			MaxSendable:         c.Convertible.MaxSendable,
			Decimals:            c.Decimals,
		})
	}
	return json.Marshal(&v1Currency{
		Code:                c.Code,
		Name:                c.Name,
		Symbol:              c.Symbol,
		MillisatoshiPerUnit: c.MillisatoshiPerUnit,
		Convertible:         c.Convertible,
		Decimals:            c.Decimals,
	})
}

func (c *Currency) UnmarshalJSON(data []byte) error {
	jsonData := make(map[string]interface{})
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return err
	}
	if _, ok := jsonData["minSendable"]; ok {
		v0 := &v0Currency{}
		if err := json.Unmarshal(data, v0); err != nil {
			return err
		}
		c.Code = v0.Code
		c.Name = v0.Name
		c.Symbol = v0.Symbol
		c.MillisatoshiPerUnit = v0.MillisatoshiPerUnit
		c.Convertible.MinSendable = v0.MinSendable
		c.Convertible.MaxSendable = v0.MaxSendable
		c.Decimals = v0.Decimals
		c.UmaMajorVersion = 0
		return nil
	}
	v1 := &v1Currency{}
	if err := json.Unmarshal(data, v1); err != nil {
		return err
	}
	c.Code = v1.Code
	c.Name = v1.Name
	c.Symbol = v1.Symbol
	c.MillisatoshiPerUnit = v1.MillisatoshiPerUnit
	c.Convertible = v1.Convertible
	c.Decimals = v1.Decimals
	c.UmaMajorVersion = 1
	return nil
}

package uma

type Currency struct {
	// Code is the ISO 4217 currency code (eg. USD).
	Code string `json:"code"`

	// Name is the full display name of the currency (eg. US Dollars).
	Name string `json:"name"`

	// Symbol is the symbol of the currency (eg. $ for USD).
	Symbol string `json:"symbol"`

	// MillisatoshiPerUnit is the estimated millisats per smallest "unit" of this currency (eg. 1 cent in USD).
	MillisatoshiPerUnit float64 `json:"multiplier"`

	// MinSendable is the minimum amount of the currency that can be sent in a single transaction. This is in the
	// smallest unit of the currency (eg. cents for USD).
	MinSendable int64 `json:"minSendable"`

	// MaxSendable is the maximum amount of the currency that can be sent in a single transaction. This is in the
	// smallest unit of the currency (eg. cents for USD).
	MaxSendable int64 `json:"maxSendable"`

	// Decimals is the number of digits after the decimal point for display on the sender side, and to add clarity
	// around what the "smallest unit" of the currency is. For example, in USD, by convention, there are 2 digits for
	// cents - $5.95. In this case, `decimals` would be 2. Note that the multiplier is still always in the smallest
	// unit (cents). In addition to display purposes, this field can be used to resolve ambiguity in what the multiplier
	// means. For example, if the currency is "BTC" and the multiplier is 1000, really we're exchanging in SATs, so
	// `decimals` would be 8.
	// For details on edge cases and examples, see https://github.com/uma-universal-money-address/protocol/blob/main/umad-04-lnurlp-response.md.
	Decimals int `json:"decimals"`
}

package protocol

import (
	"fmt"

	"github.com/decred/dcrd/bech32"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/utils"
)

type InvoiceCurrency struct {
	// Code is the ISO 4217 (if applicable) currency code (eg. "USD"). For cryptocurrencies, this will  be a ticker
	// symbol, such as BTC for Bitcoin.
	Code string `tlv:"0"`

	// Name is the full display name of the currency (eg. US Dollars).
	Name string `tlv:"1"`

	// Symbol is the symbol of the currency (eg. $ for USD).
	Symbol string `tlv:"2"`

	// Decimals is the number of digits after the decimal point for display on the sender side
	Decimals uint8 `tlv:"3"`
}

func (c *InvoiceCurrency) MarshalTLV() ([]byte, error) {
	return utils.MarshalTLV(c)
}

func (c *InvoiceCurrency) UnmarshalTLV(data []byte) error {
	return utils.UnmarshalTLV(c, data)
}

type UmaInvoice struct {
	// Receiving UMA address
	ReceiverUma string `tlv:"0"`

	// Invoice UUID Served as both the identifier of the UMA invoice, and the validation of proof of payment.
	InvoiceUUID string `tlv:"1"`

	// The amount of invoice to be paid in the smalest unit of the ReceivingCurrency.
	Amount uint64 `tlv:"2"`

	// The currency of the invoice
	ReceivingCurrency InvoiceCurrency `tlv:"3"`

	// The unix timestamp the UMA invoice expires
	Expiration uint64 `tlv:"4"`

	// Indicates whether the VASP is a financial institution that requires travel rule information.
	IsSubjectToTravelRule bool `tlv:"5"`

	// RequiredPayerData the data about the payer that the sending VASP must provide in order to send a payment.
	RequiredPayerData *CounterPartyDataOptions `tlv:"6"`

	// UmaVersion is a list of UMA versions that the VASP supports for this transaction. It should be
	// containing the lowest minor version of each major version it supported, separated by commas.
	UmaVersion string `tlv:"7"`

	// CommentCharsAllowed is the number of characters that the sender can include in the comment field of the pay request.
	CommentCharsAllowed *int `tlv:"8"`

	// The sender's UMA address. If this field presents, the UMA invoice should directly go to the sending VASP instead of showing in other formats.
	SenderUma *string `tlv:"9"`

	// The maximum number of the invoice can be paid
	InvoiceLimit *uint64 `tlv:"10"`

	// KYC status of the receiver, default is verified.
	KycStatus *KycStatus `tlv:"11"`

	// The callback url that the sender should send the PayRequest to.
	Callback string `tlv:"12"`

	// The signature of the UMA invoice
	Signature *[]byte `tlv:"100"`
}

func (i *UmaInvoice) MarshalTLV() ([]byte, error) {
	return utils.MarshalTLV(i)
}

func (i *UmaInvoice) UnmarshalTLV(data []byte) error {
	return utils.UnmarshalTLV(i, data)
}

func (i *UmaInvoice) ToBech32String() (string, error) {
	if i.Signature == nil {
		return "", fmt.Errorf("signature is required to encode to bech32")
	}
	tlv, err := i.MarshalTLV()
	if err != nil {
		return "", err
	}
	conv, err := bech32.ConvertBits(tlv, 8, 5, true)
	if err != nil {
		return "", err
	}

	return bech32.Encode("uma", conv)
}

func FromBech32String(bech32Str string) (*UmaInvoice, error) {
	hrp, data, err := bech32.DecodeNoLimit(bech32Str)
	if err != nil {
		return nil, err
	}
	if hrp != "uma" {
		return nil, fmt.Errorf("invalid human readable part")
	}
	conv, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return nil, err
	}
	var i UmaInvoice
	err = i.UnmarshalTLV(conv)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

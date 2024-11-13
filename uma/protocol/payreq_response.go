package protocol

import (
	"encoding/json"
	"errors"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/utils"
)

// PayReqResponse is the response sent by the receiver to the sender to provide an invoice.
type PayReqResponse struct {
	// EncodedInvoice is the BOLT11 invoice that the sender will pay.
	EncodedInvoice string `json:"pr"`
	// Routes is usually just an empty list from legacy LNURL, which was replaced by route hints in the BOLT11 invoice.
	Routes []Route `json:"routes"`
	// PaymentInfo is information about the payment that the receiver will receive. Includes Final currency-related
	// information for the payment. Required for UMA.
	PaymentInfo *PayReqResponsePaymentInfo `json:"converted,omitempty"`
	// PayeeData The data about the receiver that the sending VASP requested in the payreq request.
	// Required for UMA.
	PayeeData *PayeeData `json:"payeeData,omitempty"`
	// Disposable This field may be used by a WALLET to decide whether the initial LNURL link will  be stored locally
	// for later reuse or erased. If disposable is null, it should be interpreted as true, so if SERVICE intends its
	// LNURL links to be stored it must return `disposable: false`. UMA should never return `disposable: false` due to
	// signature nonce checks, etc. See LUD-11.
	Disposable *bool `json:"disposable,omitempty"`
	// SuccessAction defines a struct which can be stored and shown to the user on payment success. See LUD-09.
	SuccessAction *map[string]string `json:"successAction,omitempty"`
	// UmaMajorVersion is the major version of the UMA protocol that the receiver is using. Only used
	// for serialization and deserialization. Not included in the JSON response.
	UmaMajorVersion int `json:"umaMajorVersion"`
}

func (p *PayReqResponse) IsUmaResponse() bool {
	if p.PaymentInfo == nil || p.PayeeData == nil {
		return false
	}
	compliance, err := p.PayeeData.Compliance()
	if err != nil {
		return false
	}
	return compliance != nil
}

type Route struct {
	Pubkey string `json:"pubkey"`
	Path   []struct {
		Pubkey   string `json:"pubkey"`
		Fee      int64  `json:"fee"`
		Msatoshi int64  `json:"msatoshi"`
		Channel  string `json:"channel"`
	} `json:"path"`
}

type PayReqResponsePaymentInfo struct {
	// Amount is the amount that the receiver will receive in the receiving currency not including fees. The amount is
	//    specified in the smallest unit of the currency (eg. cents for USD).
	Amount *int64 `json:"amount,omitempty"`
	// CurrencyCode is the currency code that the receiver will receive for this payment.
	CurrencyCode string `json:"currencyCode"`
	// Multiplier is the conversion rate. It is the number of millisatoshis that the receiver will receive for 1 unit of
	//    the specified currency. In this context, this is just for convenience. The conversion rate is also baked into
	//    the invoice amount itself.
	//    `invoice amount = Amount * Multiplier + ExchangeFeesMillisatoshi`
	Multiplier float64 `json:"multiplier"`
	// Decimals is the number of digits after the decimal point for the receiving currency. For example, in USD, by
	// convention, there are 2 digits for cents - $5.95. In this case, `Decimals` would be 2. This should align with the
	// currency's `Decimals` field in the LNURLP response. It is included here for convenience. See
	// [UMAD-04](/uma-04-local-currency.md) for details, edge cases, and examples.
	Decimals int `json:"decimals"`
	// ExchangeFeesMillisatoshi is the fees charged (in millisats) by the receiving VASP for this transaction. This is
	// separate from the Multiplier.
	ExchangeFeesMillisatoshi int64 `json:"fee"`
}

type v0PayReqResponsePaymentInfo struct {
	CurrencyCode             string  `json:"currencyCode"`
	Multiplier               float64 `json:"multiplier"`
	Decimals                 int     `json:"decimals"`
	ExchangeFeesMillisatoshi int64   `json:"exchangeFeesMillisatoshi"`
}

type v0PayReqResponse struct {
	EncodedInvoice string                       `json:"pr"`
	Routes         []Route                      `json:"routes"`
	PaymentInfo    *v0PayReqResponsePaymentInfo `json:"paymentInfo,omitempty"`
	PayeeData      *PayeeData                   `json:"payeeData,omitempty"`
	Disposable     *bool                        `json:"disposable,omitempty"`
	SuccessAction  *map[string]string           `json:"successAction,omitempty"`
	Compliance     *CompliancePayeeData         `json:"compliance,omitempty"`
}

type v1PayReqResponse struct {
	EncodedInvoice string                     `json:"pr"`
	Routes         []Route                    `json:"routes"`
	PaymentInfo    *PayReqResponsePaymentInfo `json:"converted,omitempty"`
	PayeeData      *PayeeData                 `json:"payeeData,omitempty"`
	Disposable     *bool                      `json:"disposable,omitempty"`
	SuccessAction  *map[string]string         `json:"successAction,omitempty"`
}

func (p *PayReqResponse) asV0() (*v0PayReqResponse, error) {
	if p.UmaMajorVersion != 0 {
		return nil, errors.New("not a v0 response")
	}
	compliance, err := p.PayeeData.Compliance()
	if err != nil {
		return nil, err
	}
	var v0PaymentInfo *v0PayReqResponsePaymentInfo
	if p.PaymentInfo != nil {
		v0PaymentInfo = &v0PayReqResponsePaymentInfo{
			CurrencyCode:             p.PaymentInfo.CurrencyCode,
			Multiplier:               p.PaymentInfo.Multiplier,
			Decimals:                 p.PaymentInfo.Decimals,
			ExchangeFeesMillisatoshi: p.PaymentInfo.ExchangeFeesMillisatoshi,
		}
	}
	return &v0PayReqResponse{
		EncodedInvoice: p.EncodedInvoice,
		Routes:         p.Routes,
		PaymentInfo:    v0PaymentInfo,
		PayeeData:      p.PayeeData,
		Disposable:     p.Disposable,
		SuccessAction:  p.SuccessAction,
		Compliance:     compliance,
	}, nil
}

func (p *PayReqResponse) asV1() *v1PayReqResponse {
	if p.UmaMajorVersion != 1 {
		return nil
	}
	return &v1PayReqResponse{
		EncodedInvoice: p.EncodedInvoice,
		Routes:         p.Routes,
		PaymentInfo:    p.PaymentInfo,
		PayeeData:      p.PayeeData,
		Disposable:     p.Disposable,
		SuccessAction:  p.SuccessAction,
	}
}

func (p *PayReqResponse) MarshalJSON() ([]byte, error) {
	if p.UmaMajorVersion == 0 {
		v0, err := p.asV0()
		if err != nil {
			return nil, err
		}
		return json.Marshal(v0)
	}
	return json.Marshal(p.asV1())
}

func (p *PayReqResponse) UnmarshalJSON(data []byte) error {
	dataAsMap := make(map[string]interface{})
	err := json.Unmarshal(data, &dataAsMap)
	if err != nil {
		return err
	}
	umaVersion := 1
	if _, ok := dataAsMap["paymentInfo"]; ok {
		umaVersion = 0
	}
	if umaVersion == 0 {
		var v0 v0PayReqResponse
		err := json.Unmarshal(data, &v0)
		if err != nil {
			return err
		}
		var paymentInfo *PayReqResponsePaymentInfo
		if v0.PaymentInfo != nil {
			paymentInfo = &PayReqResponsePaymentInfo{
				CurrencyCode:             v0.PaymentInfo.CurrencyCode,
				Multiplier:               v0.PaymentInfo.Multiplier,
				Decimals:                 v0.PaymentInfo.Decimals,
				ExchangeFeesMillisatoshi: v0.PaymentInfo.ExchangeFeesMillisatoshi,
			}
		}
		if v0.Compliance != nil {
			if v0.PayeeData == nil {
				v0.PayeeData = &PayeeData{}
			}
			complianceMap, err := v0.Compliance.AsMap()
			if err != nil {
				return err
			}
			(*v0.PayeeData)["compliance"] = complianceMap
		}
		p.UmaMajorVersion = 0
		p.EncodedInvoice = v0.EncodedInvoice
		p.Routes = v0.Routes
		p.PaymentInfo = paymentInfo
		p.PayeeData = v0.PayeeData
		p.Disposable = v0.Disposable
		p.SuccessAction = v0.SuccessAction
		return nil
	}

	var v1 v1PayReqResponse
	err = json.Unmarshal(data, &v1)
	if err != nil {
		return err
	}
	p.UmaMajorVersion = 1
	p.EncodedInvoice = v1.EncodedInvoice
	p.Routes = v1.Routes
	p.PaymentInfo = v1.PaymentInfo
	p.PayeeData = v1.PayeeData
	p.Disposable = v1.Disposable
	p.SuccessAction = v1.SuccessAction
	return nil
}

// Append a backing signature to the PayReqResponse.
//
// Args:
//
//	signingPrivateKey: the private key to use to sign the payload.
//	domain: the domain of the VASP that is signing the payload. The associated public key will be fetched from
//	/.well-known/lnurlpubkey on this domain to verify the signature.
//	payerIdentifier: the identifier of the sender. For example, $alice@vasp1.com
//	payeeIdentifier: the identifier of the receiver. For example, $bob@vasp2.com
func (p *PayReqResponse) AppendBackingSignature(
	signingPrivateKey []byte,
	domain string,
	payerIdentifier string,
	payeeIdentifier string,
) error {
	complianceData, err := p.PayeeData.Compliance()
	if err != nil {
		return err
	}
	if complianceData == nil {
		return errors.New("compliance payee data is missing")
	}
	signablePayload, err := complianceData.SignablePayload(payerIdentifier, payeeIdentifier)
	if err != nil {
		return err
	}
	signature, err := utils.SignPayload(signablePayload, signingPrivateKey)
	if err != nil {
		return err
	}
	if complianceData.BackingSignatures == nil {
		complianceData.BackingSignatures = &[]BackingSignature{}
	}
	*complianceData.BackingSignatures = append(*complianceData.BackingSignatures, BackingSignature{
		Signature: *signature,
		Domain:    domain,
	})
	complianceMap, err := complianceData.AsMap()
	if err != nil {
		return err
	}
	(*p.PayeeData)["compliance"] = complianceMap
	return nil
}

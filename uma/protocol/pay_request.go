package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/utils"
	"net/url"
	"strconv"
	"strings"
)

// PayRequest is the request sent by the sender to the receiver to retrieve an invoice.
type PayRequest struct {
	// SendingAmountCurrencyCode is the currency code of the `amount` field. `nil` indicates that `amount` is in
	// millisatoshis as in LNURL without LUD-21. If this is not `nil`, then `amount` is in the smallest unit of the
	// specified currency (e.g. cents for USD). This currency code can be any currency which the receiver can quote.
	// However, there are two most common scenarios for UMA:
	//
	// 1. If the sender wants the receiver wants to receive a specific amount in their receiving
	// currency, then this field should be the same as `receiving_currency_code`. This is useful
	// for cases where the sender wants to ensure that the receiver receives a specific amount
	// in that destination currency, regardless of the exchange rate, for example, when paying
	// for some goods or services in a foreign currency.
	//
	// 2. If the sender has a specific amount in their own currency that they would like to send,
	// then this field should be left as `None` to indicate that the amount is in millisatoshis.
	// This will lock the sent amount on the sender side, and the receiver will receive the
	// equivalent amount in their receiving currency. NOTE: In this scenario, the sending VASP
	// *should not* pass the sending currency code here, as it is not relevant to the receiver.
	// Rather, by specifying an invoice amount in msats, the sending VASP can ensure that their
	// user will be sending a fixed amount, regardless of the exchange rate on the receiving side.
	SendingAmountCurrencyCode *string `json:"sendingAmountCurrencyCode,omitempty"`
	// ReceivingCurrencyCode is the ISO 3-digit currency code that the receiver will receive for this payment. Defaults
	// to amount being specified in msats if this is not provided.
	ReceivingCurrencyCode *string `json:"convert,omitempty"`
	// Amount is the amount that the receiver will receive for this payment in the smallest unit of the specified
	// currency (i.e. cents for USD) if `SendingAmountCurrencyCode` is not `nil`. Otherwise, it is the amount in
	// millisatoshis.
	Amount int64 `json:"amount"`
	// PayerData is the data that the sender will send to the receiver to identify themselves. Required for UMA, as is
	// the `compliance` field in the `payerData` object.
	PayerData *PayerData `json:"payerData,omitempty"`
	// RequestedPayeeData is the data that the sender is requesting about the payee.
	RequestedPayeeData *CounterPartyDataOptions `json:"payeeData,omitempty"`
	// Comment is a comment that the sender would like to include with the payment. This can only be included
	// if the receiver included the `commentAllowed` field in the lnurlp response. The length of
	// the comment must be less than or equal to the value of `commentAllowed`.
	Comment *string `json:"comment,omitempty"`
	// InvoiceUUID is the invoice UUID that the sender is paying.
	// This only exists in the v1 pay request since the v0 SDK won't support invoices.
	InvoiceUUID *string `json:"invoiceUUID,omitempty"`
	// UmaMajorVersion is the major version of the UMA protocol that the VASP supports for this currency. This is used
	// for serialization, but is not serialized itself.
	UmaMajorVersion int `json:"-"`
}

type v0PayRequest struct {
	ReceivingCurrencyCode *string                  `json:"currency,omitempty"`
	Amount                int64                    `json:"amount"`
	PayerData             *PayerData               `json:"payerData,omitempty"`
	RequestedPayeeData    *CounterPartyDataOptions `json:"payeeData,omitempty"`
	Comment               *string                  `json:"comment,omitempty"`
}

type v1PayRequest struct {
	ReceivingCurrencyCode *string                  `json:"convert,omitempty"`
	Amount                string                   `json:"amount"`
	PayerData             *PayerData               `json:"payerData,omitempty"`
	RequestedPayeeData    *CounterPartyDataOptions `json:"payeeData,omitempty"`
	Comment               *string                  `json:"comment,omitempty"`
	InvoiceUUID           *string                  `json:"invoiceUUID,omitempty"`
}

// IsUmaRequest returns true if the request is a valid UMA request, otherwise, if any fields are missing, it returns false.
func (p *PayRequest) IsUmaRequest() bool {
	if p.PayerData == nil {
		return false
	}

	compliance, err := p.PayerData.Compliance()
	if err != nil {
		return false
	}

	return compliance != nil && p.PayerData.Identifier() != nil
}

func (p *PayRequest) MarshalJSON() ([]byte, error) {
	if p.UmaMajorVersion == 0 {
		return json.Marshal(&v0PayRequest{
			ReceivingCurrencyCode: p.ReceivingCurrencyCode,
			Amount:                p.Amount,
			PayerData:             p.PayerData,
			RequestedPayeeData:    p.RequestedPayeeData,
			Comment:               p.Comment,
		})
	}

	amount := strconv.FormatInt(p.Amount, 10)
	if p.SendingAmountCurrencyCode != nil {
		amount = fmt.Sprintf("%s.%s", amount, *p.SendingAmountCurrencyCode)
	}
	return json.Marshal(&v1PayRequest{
		ReceivingCurrencyCode: p.ReceivingCurrencyCode,
		Amount:                amount,
		PayerData:             p.PayerData,
		RequestedPayeeData:    p.RequestedPayeeData,
		Comment:               p.Comment,
	})
}

func (p *PayRequest) UnmarshalJSON(data []byte) error {
	var rawReq map[string]interface{}
	err := json.Unmarshal(data, &rawReq)
	if err != nil {
		return err
	}
	isAmountString := false
	if _, ok := rawReq["amount"].(string); ok {
		isAmountString = true
	} else {
		_, ok = rawReq["amount"].(float64)
		if !ok {
			return errors.New("missing or invalid amount field")
		}
	}
	isUma := false
	payerData, ok := rawReq["payerData"].(map[string]interface{})
	if ok {
		_, ok = payerData["compliance"].(map[string]interface{})
		if ok {
			isUma = true
		}
	}
	isV1 := false
	if _, ok := rawReq["convert"].(string); ok {
		isV1 = isUma
	}
	if isV1 || isAmountString {
		var v1Req v1PayRequest
		err = json.Unmarshal(data, &v1Req)
		if err != nil {
			return err
		}
		return p.UnmarshalFromV1(v1Req)
	}
	var v0Req v0PayRequest
	err = json.Unmarshal(data, &v0Req)
	if err != nil {
		return err
	}
	err = p.UnmarshalFromV0(v0Req)
	if err != nil {
		return err
	}
	return nil
}

func (p *PayRequest) UnmarshalFromV1(request v1PayRequest) error {
	p.UmaMajorVersion = 1
	p.ReceivingCurrencyCode = request.ReceivingCurrencyCode
	p.PayerData = request.PayerData
	p.RequestedPayeeData = request.RequestedPayeeData
	p.Comment = request.Comment
	amount := request.Amount
	amountParts := strings.Split(amount, ".")
	if len(amountParts) > 2 {
		return errors.New("invalid amount field")
	}
	var err error
	p.Amount, err = strconv.ParseInt(amountParts[0], 10, 64)
	if err != nil {
		return err
	}
	if len(amountParts) == 2 && len(amountParts[1]) > 0 {
		p.SendingAmountCurrencyCode = &amountParts[1]
	}
	return nil
}

func (p *PayRequest) UnmarshalFromV0(request v0PayRequest) error {
	p.UmaMajorVersion = 0
	p.ReceivingCurrencyCode = request.ReceivingCurrencyCode
	p.PayerData = request.PayerData
	p.RequestedPayeeData = request.RequestedPayeeData
	p.Comment = request.Comment
	p.Amount = request.Amount
	return nil
}

func (p *PayRequest) Encode() ([]byte, error) {
	return p.MarshalJSON()
}

func (p *PayRequest) EncodeAsUrlParams() (*url.Values, error) {
	jsonBytes, err := p.MarshalJSON()
	if err != nil {
		return nil, err
	}
	jsonMap := make(map[string]interface{})
	err = json.Unmarshal(jsonBytes, &jsonMap)
	if err != nil {
		return nil, err
	}
	payReqParams := url.Values{}
	for key, value := range jsonMap {
		valueString, ok := value.(string)
		if ok {
			payReqParams.Add(key, valueString)
		} else {
			valueBytes, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			payReqParams.Add(key, string(valueBytes))
		}
	}
	return &payReqParams, nil
}

func (p *PayRequest) SignablePayload() ([]byte, error) {
	if p.PayerData == nil {
		return nil, errors.New("payer data is missing")
	}
	senderAddress := p.PayerData.Identifier()
	if senderAddress == nil || *senderAddress == "" {
		return nil, errors.New("payer data identifier is missing")
	}
	complianceData, err := p.PayerData.Compliance()
	if err != nil {
		return nil, err
	}
	if complianceData == nil {
		return nil, errors.New("compliance payer data is missing")
	}
	signatureNonce := complianceData.SignatureNonce
	signatureTimestamp := complianceData.SignatureTimestamp
	payloadString := strings.Join([]string{
		*senderAddress,
		signatureNonce,
		strconv.FormatInt(signatureTimestamp, 10),
	}, "|")
	return []byte(payloadString), nil
}

// Append a backing signature to the PayRequest.
//
// Args:
//
//	signingPrivateKey: the private key to use to sign the payload.
//	domain: the domain of the VASP that is signing the payload. The associated public key will be fetched from
//	/.well-known/lnurlpubkey on this domain to verify the signature.
func (p *PayRequest) AppendBackingSignature(signingPrivateKey []byte, domain string) error {
	signablePayload, err := p.SignablePayload()
	if err != nil {
		return err
	}
	signature, err := utils.SignPayload(signablePayload, signingPrivateKey)
	if err != nil {
		return err
	}
	complianceData, err := p.PayerData.Compliance()
	if err != nil {
		return err
	}
	if complianceData == nil {
		return errors.New("compliance payer data is missing")
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
	(*p.PayerData)["compliance"] = complianceMap
	return nil
}

// ParsePayRequestFromQueryParams Parses a pay request from query parameters.
// This is useful for parsing a non-UMA pay request from a URL query since raw LNURL uses a GET request for the payreq,
// whereas UMA uses a POST request.
func ParsePayRequestFromQueryParams(query url.Values) (*PayRequest, error) {
	amountStr := query.Get("amount")
	if amountStr == "" {
		return nil, errors.New("missing amount")
	}
	amountParts := strings.Split(amountStr, ".")
	if len(amountParts) > 2 {
		return nil, errors.New("invalid amount")
	}
	amount, err := strconv.ParseInt(amountParts[0], 10, 64)
	if err != nil {
		return nil, err
	}
	var sendingAmountCurrencyCode *string
	if len(amountParts) == 2 {
		sendingAmountCurrencyCode = &amountParts[1]
	}
	v1ReceivingCurrencyCodeStr := query.Get("convert")
	v0ReceivingCurrencyCodeStr := query.Get("currency")
	umaMajorVersion := 1
	var receivingCurrencyCode *string
	if v1ReceivingCurrencyCodeStr != "" {
		receivingCurrencyCode = &v1ReceivingCurrencyCodeStr
	} else if v0ReceivingCurrencyCodeStr != "" {
		receivingCurrencyCode = &v0ReceivingCurrencyCodeStr
		umaMajorVersion = 0
	}

	payerData := query.Get("payerData")
	var payerDataObj *PayerData
	if payerData != "" {
		err = json.Unmarshal([]byte(payerData), &payerDataObj)
		if err != nil {
			return nil, err
		}
	}
	requestedPayeeData := query.Get("payeeData")
	var requestedPayeeDataObj *CounterPartyDataOptions
	if requestedPayeeData != "" {
		err = json.Unmarshal([]byte(requestedPayeeData), &requestedPayeeDataObj)
		if err != nil {
			return nil, err
		}
	}
	commentParam := query.Get("comment")
	var comment *string
	if commentParam != "" {
		comment = &commentParam
	}

	return &PayRequest{
		SendingAmountCurrencyCode: sendingAmountCurrencyCode,
		ReceivingCurrencyCode:     receivingCurrencyCode,
		Amount:                    amount,
		PayerData:                 payerDataObj,
		RequestedPayeeData:        requestedPayeeDataObj,
		Comment:                   comment,
		UmaMajorVersion:           umaMajorVersion,
	}, nil
}

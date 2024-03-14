package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
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
	SendingAmountCurrencyCode *string `json:"sendingAmountCurrencyCode"`
	// ReceivingCurrencyCode is the ISO 3-digit currency code that the receiver will receive for this payment. Defaults
	// to amount being specified in msats if this is not provided.
	ReceivingCurrencyCode *string `json:"convert"`
	// Amount is the amount that the receiver will receive for this payment in the smallest unit of the specified
	// currency (i.e. cents for USD) if `SendingAmountCurrencyCode` is not `nil`. Otherwise, it is the amount in
	// millisatoshis.
	Amount int64 `json:"amount"`
	// PayerData is the data that the sender will send to the receiver to identify themselves. Required for UMA, as is
	// the `compliance` field in the `payerData` object.
	PayerData *PayerData `json:"payerData"`
	// RequestedPayeeData is the data that the sender is requesting about the payee.
	RequestedPayeeData *CounterPartyDataOptions `json:"payeeData"`
	// Comment is a comment that the sender would like to include with the payment. This can only be included
	// if the receiver included the `commentAllowed` field in the lnurlp response. The length of
	// the comment must be less than or equal to the value of `commentAllowed`.
	Comment *string `json:"comment"`
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
	amount := strconv.FormatInt(p.Amount, 10)
	if p.SendingAmountCurrencyCode != nil {
		amount = fmt.Sprintf("%s.%s", amount, *p.SendingAmountCurrencyCode)
	}
	var payerDataJson []byte
	if p.PayerData != nil {
		var err error
		payerDataJson, err = json.Marshal(p.PayerData)
		if err != nil {
			return nil, err
		}
	}
	reqStr := fmt.Sprintf(`{
		"amount": "%s"`, amount)
	if p.ReceivingCurrencyCode != nil {
		reqStr += fmt.Sprintf(`,
		"convert": "%s"`, *p.ReceivingCurrencyCode)
	}
	if p.PayerData != nil {
		reqStr += fmt.Sprintf(`,
		"payerData": %s`, payerDataJson)
	}
	if p.RequestedPayeeData != nil {
		payeeDataJson, err := json.Marshal(p.RequestedPayeeData)
		if err != nil {
			return nil, err
		}
		reqStr += fmt.Sprintf(`,
		"payeeData": %s`, payeeDataJson)
	}
	if p.Comment != nil {
		reqStr += fmt.Sprintf(`,
		"comment": "%s"`, *p.Comment)
	}
	reqStr += "}"
	return []byte(reqStr), nil
}

func (p *PayRequest) UnmarshalJSON(data []byte) error {
	var rawReq map[string]interface{}
	err := json.Unmarshal(data, &rawReq)
	if err != nil {
		return err
	}
	convert, ok := rawReq["convert"].(string)
	if ok {
		p.ReceivingCurrencyCode = &convert
	}
	amount, ok := rawReq["amount"].(string)
	if !ok {
		return errors.New("missing or invalid amount field")
	}
	amountParts := strings.Split(amount, ".")
	if len(amountParts) > 2 {
		return errors.New("invalid amount field")
	}
	p.Amount, err = strconv.ParseInt(amountParts[0], 10, 64)
	if err != nil {
		return err
	}
	if len(amountParts) == 2 && len(amountParts[1]) > 0 {
		p.SendingAmountCurrencyCode = &amountParts[1]
	}
	payerDataJson, ok := rawReq["payerData"].(map[string]interface{})
	if ok {
		payerDataJsonBytes, err := json.Marshal(payerDataJson)
		if err != nil {
			return err
		}
		var payerData PayerData
		err = json.Unmarshal(payerDataJsonBytes, &payerData)
		if err != nil {
			return err
		}
		p.PayerData = &payerData
	}
	payeeDataJson, ok := rawReq["payeeData"].(map[string]interface{})
	if ok {
		payeeDataJsonBytes, err := json.Marshal(payeeDataJson)
		if err != nil {
			return err
		}
		var payeeData CounterPartyDataOptions
		err = json.Unmarshal(payeeDataJsonBytes, &payeeData)
		if err != nil {
			return err
		}
		p.RequestedPayeeData = &payeeData
	}
	comment, ok := rawReq["comment"].(string)
	if ok {
		p.Comment = &comment
	}
	return nil
}

func (p *PayRequest) Encode() ([]byte, error) {
	return json.Marshal(p)
}

func (p *PayRequest) EncodeAsUrlParams() (*url.Values, error) {
	jsonBytes, err := json.Marshal(p)
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

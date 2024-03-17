package uma_test

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	umaprotocol "github.com/uma-universal-money-address/uma-go-sdk/uma/protocol"
	"testing"
)

func TestParseV0Currency(t *testing.T) {
	currency := umaprotocol.Currency{
		Code:                "USD",
		Symbol:              "$",
		Name:                "US Dollar",
		MillisatoshiPerUnit: 12345,
		Convertible: umaprotocol.ConvertibleCurrency{
			MinSendable: 100,
			MaxSendable: 100000000,
		},
		Decimals:        2,
		UmaMajorVersion: 0,
	}

	currencyJson, err := currency.MarshalJSON()
	require.NoError(t, err)
	currencyJsonMap := make(map[string]interface{})
	err = json.Unmarshal(currencyJson, &currencyJsonMap)
	require.NoError(t, err)
	require.Equal(t, "USD", currencyJsonMap["code"])
	require.Equal(t, "$", currencyJsonMap["symbol"])
	require.Equal(t, "US Dollar", currencyJsonMap["name"])
	require.Equal(t, 12345.0, currencyJsonMap["multiplier"])
	require.Equal(t, 100.0, currencyJsonMap["minSendable"])
	require.Equal(t, 100000000.0, currencyJsonMap["maxSendable"])
	require.Equal(t, 2.0, currencyJsonMap["decimals"])

	reserializedCurrency := umaprotocol.Currency{}
	err = json.Unmarshal(currencyJson, &reserializedCurrency)
	require.NoError(t, err)
	require.Equal(t, currency, reserializedCurrency)
}

func TestV0LnurlpResponse(t *testing.T) {
	currencies := []umaprotocol.Currency{
		{
			Code:                "USD",
			Symbol:              "$",
			Name:                "US Dollar",
			MillisatoshiPerUnit: 12345,
			Convertible: umaprotocol.ConvertibleCurrency{
				MinSendable: 100,
				MaxSendable: 100000000,
			},
			Decimals:        2,
			UmaMajorVersion: 0,
		},
	}
	umaVersion := "0.3"
	lnurlpResponse := umaprotocol.LnurlpResponse{
		Callback:        "https://example.com/lnurlp",
		Tag:             "withdrawRequest",
		MinSendable:     1000,
		MaxSendable:     1000000,
		Currencies:      &currencies,
		EncodedMetadata: "metadata",
		UmaVersion:      &umaVersion,
	}

	lnurlpResponseJson, err := json.Marshal(lnurlpResponse)
	require.NoError(t, err)
	lnurlpResponseJsonMap := make(map[string]interface{})
	err = json.Unmarshal(lnurlpResponseJson, &lnurlpResponseJsonMap)
	require.NoError(t, err)
	require.Equal(t, "https://example.com/lnurlp", lnurlpResponseJsonMap["callback"])
	require.Equal(t, "withdrawRequest", lnurlpResponseJsonMap["tag"])
	require.Equal(t, 1000.0, lnurlpResponseJsonMap["minSendable"])
	require.Equal(t, 1000000.0, lnurlpResponseJsonMap["maxSendable"])
	require.Equal(t, "metadata", lnurlpResponseJsonMap["metadata"])
	require.Equal(t, "0.3", lnurlpResponseJsonMap["umaVersion"])
	require.Equal(t, 100.0, lnurlpResponseJsonMap["currencies"].([]interface{})[0].(map[string]interface{})["minSendable"])
	require.Equal(t, 100000000.0, lnurlpResponseJsonMap["currencies"].([]interface{})[0].(map[string]interface{})["maxSendable"])

	reserializedLnurlpResponse := umaprotocol.LnurlpResponse{}
	err = json.Unmarshal(lnurlpResponseJson, &reserializedLnurlpResponse)
	require.NoError(t, err)
	require.Equal(t, lnurlpResponse, reserializedLnurlpResponse)
}

func TestV0PayRequest(t *testing.T) {
	payerData := umaprotocol.PayerData{
		"identifier": "$foo@bar.com",
		"name":       "Foo Bar",
		"email":      "email@themail.com",
	}
	currencyCode := "USD"
	comment := "comment"
	payRequest := umaprotocol.PayRequest{
		ReceivingCurrencyCode: &currencyCode,
		Amount:                1000,
		PayerData:             &payerData,
		UmaMajorVersion:       0,
		Comment:               &comment,
	}

	payRequestJson, err := payRequest.MarshalJSON()
	require.NoError(t, err)
	payRequestJsonMap := make(map[string]interface{})
	err = json.Unmarshal(payRequestJson, &payRequestJsonMap)
	require.NoError(t, err)
	require.Equal(t, "USD", payRequestJsonMap["currency"])
	require.Equal(t, 1000.0, payRequestJsonMap["amount"])
	require.Equal(t, "$foo@bar.com", payRequestJsonMap["payerData"].(map[string]interface{})["identifier"])
	require.Equal(t, "Foo Bar", payRequestJsonMap["payerData"].(map[string]interface{})["name"])
	require.Equal(t, "email@themail.com", payRequestJsonMap["payerData"].(map[string]interface{})["email"])
	require.Equal(t, "comment", payRequestJsonMap["comment"])

	reserializedPayRequest := umaprotocol.PayRequest{}
	err = json.Unmarshal(payRequestJson, &reserializedPayRequest)
	require.NoError(t, err)
	require.Equal(t, payRequest, reserializedPayRequest)
}

func TestParseV1PayReq(t *testing.T) {
	payerData := umaprotocol.PayerData{
		"identifier": "$foo@bar.com",
		"name":       "Foo Bar",
		"email":      "email@themail.com",
	}
	currencyCode := "USD"
	comment := "comment"
	payRequest := umaprotocol.PayRequest{
		ReceivingCurrencyCode:     &currencyCode,
		SendingAmountCurrencyCode: &currencyCode,
		Amount:                    1000,
		PayerData:                 &payerData,
		UmaMajorVersion:           1,
		Comment:                   &comment,
	}

	payRequestJson, err := payRequest.MarshalJSON()
	require.NoError(t, err)
	payRequestJsonMap := make(map[string]interface{})
	err = json.Unmarshal(payRequestJson, &payRequestJsonMap)
	require.NoError(t, err)
	require.Equal(t, "USD", payRequestJsonMap["convert"])
	require.Equal(t, "1000.USD", payRequestJsonMap["amount"])
	require.Equal(t, "$foo@bar.com", payRequestJsonMap["payerData"].(map[string]interface{})["identifier"])
	require.Equal(t, "Foo Bar", payRequestJsonMap["payerData"].(map[string]interface{})["name"])
	require.Equal(t, "email@themail.com", payRequestJsonMap["payerData"].(map[string]interface{})["email"])
	require.Equal(t, "comment", payRequestJsonMap["comment"])

	reserializedPayRequest := umaprotocol.PayRequest{}
	err = json.Unmarshal(payRequestJson, &reserializedPayRequest)
	require.NoError(t, err)
	require.Equal(t, payRequest, reserializedPayRequest)
}

func TestParseV0PayReqResponse(t *testing.T) {
	payReqRespJson := `{
		"pr": "lnbc1000n1p0u3",
		"routes": [],
		"compliance": {
			"nodePubKey": "02",
			"utxos": ["txid"],
			"utxoCallback": "https://example.com/utxo"
		},
		"paymentInfo": {
			"currencyCode": "USD",
			"multiplier": 1000,
			"decimals": 2,
			"exchangeFeesMillisatoshi": 1000
		}
	}`
	payReqResp := umaprotocol.PayReqResponse{}
	err := json.Unmarshal([]byte(payReqRespJson), &payReqResp)
	require.NoError(t, err)
	require.Equal(t, "lnbc1000n1p0u3", payReqResp.EncodedInvoice)
	require.Equal(t, "USD", payReqResp.PaymentInfo.CurrencyCode)
	require.Equal(t, 1000.0, payReqResp.PaymentInfo.Multiplier)
	require.Equal(t, 2, payReqResp.PaymentInfo.Decimals)
	require.Equal(t, int64(1000), payReqResp.PaymentInfo.ExchangeFeesMillisatoshi)
	compliance, err := payReqResp.PayeeData.Compliance()
	require.NoError(t, err)
	require.NotNilf(t, compliance, "compliance is nil")
	require.Equal(t, "02", *(compliance.NodePubKey))
	require.Equal(t, []string{"txid"}, compliance.Utxos)
	require.Equal(t, "https://example.com/utxo", *(compliance.UtxoCallback))
	require.Equal(t, 0, payReqResp.UmaMajorVersion)
}

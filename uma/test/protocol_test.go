package uma_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/uma-universal-money-address/uma-go-sdk/uma"
	umaprotocol "github.com/uma-universal-money-address/uma-go-sdk/uma/protocol"
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

func TestEncodeAndParsePubKeyResponse(t *testing.T) {
	pubKeyHex := "04419c5467ea563f0010fd614f85e885ac99c21b8e8d416241175fdd5efd2244fe907e2e6fa3dd6631b1b17cd28798da8d882a34c4776d44cc4090781c7aadea1b"
	pemCertChain := `-----BEGIN CERTIFICATE-----
MIIB1zCCAXygAwIBAgIUGN3ihBj1RnKoeTM/auDFnNoThR4wCgYIKoZIzj0EAwIw
QjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCmNhbGlmb3JuaWExDjAMBgNVBAcMBWxv
cyBhMQ4wDAYDVQQKDAVsaWdodDAeFw0yNDAzMDUyMTAzMTJaFw0yNDAzMTkyMTAz
MTJaMEIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApjYWxpZm9ybmlhMQ4wDAYDVQQH
DAVsb3MgYTEOMAwGA1UECgwFbGlnaHQwVjAQBgcqhkjOPQIBBgUrgQQACgNCAARB
nFRn6lY/ABD9YU+F6IWsmcIbjo1BYkEXX91e/SJE/pB+Lm+j3WYxsbF80oeY2o2I
KjTEd21EzECQeBx6reobo1MwUTAdBgNVHQ4EFgQUU87LnQdiP6XIE6LoKU1PZnbt
bMwwHwYDVR0jBBgwFoAUU87LnQdiP6XIE6LoKU1PZnbtbMwwDwYDVR0TAQH/BAUw
AwEB/zAKBggqhkjOPQQDAgNJADBGAiEAvsrvoeo3rbgZdTHxEUIgP0ArLyiO34oz
NlwL4gk5GpgCIQCvRx4PAyXNV9T6RRE+3wFlqwluOc/pPOjgdRw/wpoNPQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICdjCCAV6gAwIBAgIUAekCcU1Qhjo2Y6L2Down9BLdfdUwDQYJKoZIhvcNAQEL
BQAwNDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAmNhMQwwCgYDVQQHDANsb3MxCjAI
BgNVBAoMAWEwHhcNMjQwMzA4MDEwNTU3WhcNMjUwMzA4MDEwNTU3WjBAMQswCQYD
VQQGEwJVUzELMAkGA1UECAwCY2ExDDAKBgNVBAcMA2xvczEKMAgGA1UECgwBYTEK
MAgGA1UECwwBYTBWMBAGByqGSM49AgEGBSuBBAAKA0IABJ11ZAQKylgIzZmuI5NE
+DyZ9BUDZhxUPSxTxl+s1am+Lxzr9D7wlwOiiqCYHFWpL6lkCmJcCC06P3RyzXIT
KmyjQjBAMB0GA1UdDgQWBBRXgW6xGB3+mTSSUKlhSiu3LS+TKTAfBgNVHSMEGDAW
gBTFmyv7+YDpK0WAOHJYAzjynmWsMDANBgkqhkiG9w0BAQsFAAOCAQEAFVAA3wo+
Hi/k+OWO/1CFqIRV/0cA8F05sBMiKVA11xB6I1y54aUV4R0jN76fOiN1jnZqTRnM
G8rZUfQgE/LPVbb1ERHQfd8yaeI+TerKdPkMseu/jnvI+dDJfQdsY7iaa7NPO0dm
t8Nz75cYW8kYuDaq0Hb6uGsywf9LGO/VjrDhyiRxmZ1Oq4JxQmLuh5SDcPfqHTR3
VbMC1b7eVXaA9O2qYS36zv8cCUSUl5sOSwM6moaFN+xLtVNJ6ZhKPNS2Gd8znhzZ
AQZcDDpXBO6ORNbhVk5A3X6eQX4Ek1HBTa3pcSUQomYAA9TIuVzL6DSot5GWS8Ek
usLY8crt6ys3KQ==
-----END CERTIFICATE-----
`
	pubKeyResponse, err := uma.GetPubKeyResponse(pemCertChain, pemCertChain, nil)
	require.NoError(t, err)

	pubKeyResponseJson, err := pubKeyResponse.MarshalJSON()
	require.NoError(t, err)
	pubKeyResponseJsonMap := make(map[string]interface{})
	err = json.Unmarshal(pubKeyResponseJson, &pubKeyResponseJsonMap)
	require.NoError(t, err)

	reserializedPubKeyResponse := umaprotocol.PubKeyResponse{}
	err = json.Unmarshal(pubKeyResponseJson, &reserializedPubKeyResponse)
	require.NoError(t, err)
	require.Equal(t, *pubKeyResponse, reserializedPubKeyResponse)

	keysOnlyPubKeyResponse := umaprotocol.PubKeyResponse{
		SigningPubKeyHex:    &pubKeyHex,
		EncryptionPubKeyHex: &pubKeyHex,
	}

	pubKeyResponseJson, err = keysOnlyPubKeyResponse.MarshalJSON()
	require.NoError(t, err)
	pubKeyResponseJsonMap = make(map[string]interface{})
	err = json.Unmarshal(pubKeyResponseJson, &pubKeyResponseJsonMap)
	require.NoError(t, err)

	reserializedPubKeyResponse = umaprotocol.PubKeyResponse{}
	err = json.Unmarshal(pubKeyResponseJson, &reserializedPubKeyResponse)
	require.NoError(t, err)
	require.Equal(t, keysOnlyPubKeyResponse, reserializedPubKeyResponse)
}

func TestBinaryCodableForCounterPartyDataOptions(t *testing.T) {
	counterPartyDataOptions := umaprotocol.CounterPartyDataOptions{
		"name":       umaprotocol.CounterPartyDataOption{Mandatory: false},
		"email":      umaprotocol.CounterPartyDataOption{Mandatory: false},
		"compliance": umaprotocol.CounterPartyDataOption{Mandatory: true},
	}
	result, err := counterPartyDataOptions.MarshalBytes()
	require.NoError(t, err)

	resultStr := string(result)
	require.Equal(t, "compliance:1,email:0,name:0", resultStr)

	counterPartyDataOptions2 := umaprotocol.CounterPartyDataOptions{}
	err = counterPartyDataOptions2.UnmarshalBytes([]byte(resultStr))
	require.NoError(t, err)
	require.Equal(t, counterPartyDataOptions, counterPartyDataOptions2)
}

func TestUMAInvoiceTLVAndBech32(t *testing.T) {
	kyc := umaprotocol.KycStatusVerified
	signature := []byte("signature")
	invoice := umaprotocol.UmaInvoice{
		ReceiverUma: "$foo@bar.com",
		InvoiceUUID: "c7c07fec-cf00-431c-916f-6c13fc4b69f9",
		Amount:      1000,
		ReceivingCurrency: umaprotocol.InvoiceCurrency{
			Code:   "USD",
			Name:   "US Dollar",
			Symbol: "$",
		},
		Expiration:            1000000,
		IsSubjectToTravelRule: true,
		RequiredPayerData: &umaprotocol.CounterPartyDataOptions{
			"name":       umaprotocol.CounterPartyDataOption{Mandatory: false},
			"email":      umaprotocol.CounterPartyDataOption{Mandatory: false},
			"compliance": umaprotocol.CounterPartyDataOption{Mandatory: true},
		},
		UmaVersion:          "0.3",
		CommentCharsAllowed: nil,
		SenderUma:           nil,
		InvoiceLimit:        nil,
		KycStatus:           &kyc,
		Callback:            "https://example.com/callback",
		Signature:           &signature,
	}

	invoiceTLV, err := invoice.MarshalTLV()
	require.NoError(t, err)

	invoice2 := umaprotocol.UmaInvoice{}
	err = invoice2.UnmarshalTLV(invoiceTLV)
	require.NoError(t, err)
	require.Equal(t, invoice, invoice2)

	bech32String, err := invoice2.ToBech32String()
	require.NoError(t, err)
	require.Equal(t, "uma1qqxzgen0daqxyctj9e3k7mgpy33nwcesxanx2cedvdnrqvpdxsenzced8ycnve3dxe3nzvmxvv6xyd3evcusypp3xqcrqqcnqqp4256yqyy425eqg3hkcmrpwgpqzfqyqucnqvpsxqcrqpgpqyrpkcm0d4cxc6tpde3k2w3393jk6ctfdsarqtrwv9kk2w3squpnqt3npvqnxrqudp68gurn8ghj7etcv9khqmr99e3k7mf0vdskcmrzv93kkeqfwd5kwmnpw36hyeg0e4m4j", bech32String)

	invoice3, err := umaprotocol.FromBech32String(bech32String)
	require.NoError(t, err)
	require.Equal(t, invoice, *invoice3)
}

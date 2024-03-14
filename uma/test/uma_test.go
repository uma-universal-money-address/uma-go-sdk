package uma_test

import (
	"encoding/hex"
	"encoding/json"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	eciesgo "github.com/ecies/go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uma-universal-money-address/uma-go-sdk/uma"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/protocol"
	"math"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	expectedTime, _ := time.Parse(time.RFC3339, "2023-07-27T22:46:08Z")
	timeSec := expectedTime.Unix()
	signature := "signature"
	isSubjectToTravelRule := true
	nonce := "12345"
	vaspDomain := "vasp1.com"
	umaVersion := "1.0"
	expectedQuery := protocol.LnurlpRequest{
		ReceiverAddress:       "bob@vasp2.com",
		Signature:             &signature,
		IsSubjectToTravelRule: &isSubjectToTravelRule,
		Nonce:                 &nonce,
		Timestamp:             &expectedTime,
		VaspDomain:            &vaspDomain,
		UmaVersion:            &umaVersion,
	}
	urlString := "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=" + strconv.FormatInt(timeSec, 10)
	urlObj, _ := url.Parse(urlString)
	query, err := uma.ParseLnurlpRequest(*urlObj)
	if err != nil || query == nil {
		t.Fatalf("Parse(%s) failed: %s", urlObj, err)
	}
	assert.ObjectsAreEqual(expectedQuery, *query)
}

func TestIsUmaQueryValid(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	assert.True(t, uma.IsUmaLnurlpQuery(*urlObj))
}

func TestIsUmaQueryMissingParams(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurlp/bob?nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&umaVersion=1.0&nonce=12345&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&umaVersion=1.0&nonce=12345&vaspDomain=vasp1.com&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	// IsSubjectToTravelRule is optional
	assert.True(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))
}

func TestIsUmaQueryInvalidPath(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurla/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))
}

func TestSignAndVerifyLnurlpRequest(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(privateKey.Serialize(), "$bob@vasp2.com", "vasp1.com", true, nil)
	require.NoError(t, err)
	query, err := uma.ParseLnurlpRequest(*queryUrl)
	require.NoError(t, err)
	assert.Equal(t, *query.UmaVersion, uma.UmaProtocolVersion)
	err = uma.VerifyUmaLnurlpQuerySignature(*query.AsUmaRequest(), privateKey.PubKey().SerializeUncompressed(), getNonceCache())
	require.NoError(t, err)
}

func TestSignAndVerifyLnurlpRequestInvalidSignature(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(privateKey.Serialize(), "$bob@vasp2.com", "vasp1.com", true, nil)
	require.NoError(t, err)
	query, err := uma.ParseLnurlpRequest(*queryUrl)
	require.NoError(t, err)
	err = uma.VerifyUmaLnurlpQuerySignature(*query.AsUmaRequest(), []byte("invalid pub key"), getNonceCache())
	require.Error(t, err)
}

func TestSignAndVerifyLnurlpRequestOldSignature(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(privateKey.Serialize(), "$bob@vasp2.com", "vasp1.com", true, nil)
	require.NoError(t, err)
	query, err := uma.ParseLnurlpRequest(*queryUrl)
	require.NoError(t, err)
	tomorrow := time.Now().AddDate(0, 0, 1)
	err = uma.VerifyUmaLnurlpQuerySignature(*query.AsUmaRequest(), privateKey.PubKey().SerializeUncompressed(), uma.NewInMemoryNonceCache(tomorrow))
	require.Error(t, err)
}

func TestSignAndVerifyLnurlpRequestDuplicateNonce(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(privateKey.Serialize(), "$bob@vasp2.com", "vasp1.com", true, nil)
	require.NoError(t, err)
	query, err := uma.ParseLnurlpRequest(*queryUrl)
	require.NoError(t, err)
	nonceCache := getNonceCache()
	err = nonceCache.CheckAndSaveNonce(query.AsUmaRequest().Nonce, query.AsUmaRequest().Timestamp)
	require.NoError(t, err)
	err = uma.VerifyUmaLnurlpQuerySignature(*query.AsUmaRequest(), privateKey.PubKey().SerializeUncompressed(), nonceCache)
	require.Error(t, err)
}

func TestSignAndVerifyLnurlpResponse(t *testing.T) {
	senderSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	serializedPrivateKey := receiverSigningPrivateKey.Serialize()
	request := createLnurlpRequest(t, senderSigningPrivateKey.Serialize())
	metadata, err := createMetadataForBob()
	require.NoError(t, err)
	isSubjectToTravelRule := true
	kycStatus := protocol.KycStatusVerified
	response, err := uma.GetLnurlpResponse(
		request,
		"https://vasp2.com/api/lnurl/payreq/$bob",
		metadata,
		1,
		10_000_000,
		&serializedPrivateKey,
		&isSubjectToTravelRule,
		&protocol.CounterPartyDataOptions{
			"name":       protocol.CounterPartyDataOption{Mandatory: false},
			"email":      protocol.CounterPartyDataOption{Mandatory: false},
			"compliance": protocol.CounterPartyDataOption{Mandatory: true},
		},
		&[]protocol.Currency{
			{
				Code:                "USD",
				Name:                "US Dollar",
				Symbol:              "$",
				MillisatoshiPerUnit: 34_150,
				Convertible: protocol.ConvertibleCurrency{
					MinSendable: 1,
					MaxSendable: 10_000_000,
				},
				Decimals: 2,
			},
		},
		&kycStatus,
		nil,
		nil,
	)
	require.NoError(t, err)
	responseJson, err := json.Marshal(response)
	require.NoError(t, err)

	response, err = uma.ParseLnurlpResponse(responseJson)
	require.NoError(t, err)
	err = uma.VerifyUmaLnurlpResponseSignature(*response.AsUmaResponse(), receiverSigningPrivateKey.PubKey().SerializeUncompressed(), getNonceCache())
	require.NoError(t, err)
}

func TestPayReqCreationAndParsing(t *testing.T) {
	senderSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverEncryptionPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	trInfo := "some TR info for VASP2"
	ivmsVersion := "101.1"
	trFormat := protocol.TravelRuleFormat{
		Type:    "IVMS",
		Version: &ivmsVersion,
	}
	payreq, err := uma.GetUmaPayRequest(
		1000,
		receiverEncryptionPrivateKey.PubKey().SerializeUncompressed(),
		senderSigningPrivateKey.Serialize(),
		"USD",
		true,
		"$alice@vasp1.com",
		nil,
		nil,
		&trInfo,
		&trFormat,
		protocol.KycStatusVerified,
		nil,
		nil,
		"/api/lnurl/utxocallback?txid=1234",
		nil,
		nil,
	)
	require.NoError(t, err)

	payreqJson, err := json.Marshal(payreq)
	require.NoError(t, err)

	// Verify the encoding format:
	parsedJsonMap := make(map[string]interface{})
	err = json.Unmarshal(payreqJson, &parsedJsonMap)
	require.NoError(t, err)
	require.Equal(t, parsedJsonMap["amount"], "1000.USD")
	require.Equal(t, parsedJsonMap["convert"], "USD")

	payreq, err = uma.ParsePayRequest(payreqJson)
	require.NoError(t, err)

	err = uma.VerifyPayReqSignature(payreq, senderSigningPrivateKey.PubKey().SerializeUncompressed(), getNonceCache())
	require.NoError(t, err)

	complianceData, err := payreq.PayerData.Compliance()
	require.NoError(t, err)
	require.Equal(t, complianceData.TravelRuleFormat, &trFormat)

	encryptedTrInfo := complianceData.EncryptedTravelRuleInfo
	require.NotNil(t, encryptedTrInfo)

	encryptedTrInfoBytes, err := hex.DecodeString(*encryptedTrInfo)
	require.NoError(t, err)
	eciesPrivKey := eciesgo.NewPrivateKeyFromBytes(receiverEncryptionPrivateKey.Serialize())
	decryptedTrInfo, err := eciesgo.Decrypt(eciesPrivKey, encryptedTrInfoBytes)
	require.NoError(t, err)
	assert.Equal(t, trInfo, string(decryptedTrInfo))
}

func TestMsatsPayReqCreationAndParsing(t *testing.T) {
	senderSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverEncryptionPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	trInfo := "some TR info for VASP2"
	ivmsVersion := "101.1"
	trFormat := protocol.TravelRuleFormat{
		Type:    "IVMS",
		Version: &ivmsVersion,
	}
	payreq, err := uma.GetUmaPayRequest(
		1000,
		receiverEncryptionPrivateKey.PubKey().SerializeUncompressed(),
		senderSigningPrivateKey.Serialize(),
		"USD",
		false,
		"$alice@vasp1.com",
		nil,
		nil,
		&trInfo,
		&trFormat,
		protocol.KycStatusVerified,
		nil,
		nil,
		"/api/lnurl/utxocallback?txid=1234",
		nil,
		nil,
	)
	require.NoError(t, err)

	payreqJson, err := json.Marshal(payreq)
	require.NoError(t, err)

	// Verify the encoding format:
	parsedJsonMap := make(map[string]interface{})
	err = json.Unmarshal(payreqJson, &parsedJsonMap)
	require.NoError(t, err)
	require.Equal(t, parsedJsonMap["amount"], "1000")
	require.Equal(t, parsedJsonMap["convert"], "USD")

	payreq, err = uma.ParsePayRequest(payreqJson)
	require.NoError(t, err)
	require.NotNil(t, payreq)
}

type FakeInvoiceCreator struct{}

func (f *FakeInvoiceCreator) CreateInvoice(int64, string) (*string, error) {
	encodedInvoice := "lnbcrt100n1p0z9j"
	return &encodedInvoice, nil
}

func TestPayReqResponseAndParsing(t *testing.T) {
	senderSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverEncryptionPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	trInfo := "some TR info for VASP2"
	payeeOptions := protocol.CounterPartyDataOptions{
		"identifier": protocol.CounterPartyDataOption{
			Mandatory: true,
		},
		"name": protocol.CounterPartyDataOption{
			Mandatory: false,
		},
	}
	payreq, err := uma.GetUmaPayRequest(
		1000,
		receiverEncryptionPrivateKey.PubKey().SerializeUncompressed(),
		senderSigningPrivateKey.Serialize(),
		"USD",
		true,
		"$alice@vasp1.com",
		nil,
		nil,
		&trInfo,
		nil,
		protocol.KycStatusVerified,
		nil,
		nil,
		"/api/lnurl/utxocallback?txid=1234",
		&payeeOptions,
		nil,
	)
	require.NoError(t, err)
	client := &FakeInvoiceCreator{}
	metadata, err := createMetadataForBob()
	require.NoError(t, err)
	payeeData := protocol.PayeeData{
		"identifier": "$bob@vasp2.com",
	}
	receivingCurrencyCode := "USD"
	receivingCurrencyDecimals := 2
	conversionRate := float64(24_150)
	fee := int64(100_000)
	serializedPrivateKey := receiverSigningPrivateKey.Serialize()
	payeeIdentifier := "$bob@vasp2.com"
	utxoCallback := "/api/lnurl/utxocallback?txid=1234"
	payreqResponse, err := uma.GetPayReqResponse(
		*payreq,
		client,
		metadata,
		&receivingCurrencyCode,
		&receivingCurrencyDecimals,
		&conversionRate,
		&fee,
		&[]string{"abcdef12345"},
		nil,
		&utxoCallback,
		&payeeData,
		&serializedPrivateKey,
		&payeeIdentifier,
		nil,
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, payreqResponse.PaymentInfo.Amount, payreq.Amount)
	require.Equal(t, payreqResponse.PaymentInfo.CurrencyCode, *payreq.ReceivingCurrencyCode)

	payreqResponseJson, err := json.Marshal(payreqResponse)
	require.NoError(t, err)

	parsedResponse, err := uma.ParsePayReqResponse(payreqResponseJson)
	require.NoError(t, err)
	originalComplianceData, err := payreqResponse.PayeeData.Compliance()
	require.NoError(t, err)
	parsedComplianceData, err := parsedResponse.PayeeData.Compliance()
	require.NoError(t, err)
	require.Equal(t, originalComplianceData, parsedComplianceData)

	err = uma.VerifyPayReqResponseSignature(
		parsedResponse,
		receiverSigningPrivateKey.PubKey().SerializeUncompressed(),
		getNonceCache(),
		"$alice@vasp1.com",
		"$bob@vasp2.com",
	)
	require.NoError(t, err)
}

func TestMsatsPayReqResponseAndParsing(t *testing.T) {
	senderSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverEncryptionPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	trInfo := "some TR info for VASP2"
	payeeOptions := protocol.CounterPartyDataOptions{
		"identifier": protocol.CounterPartyDataOption{
			Mandatory: true,
		},
		"name": protocol.CounterPartyDataOption{
			Mandatory: false,
		},
	}
	payreq, err := uma.GetUmaPayRequest(
		1_000_000,
		receiverEncryptionPrivateKey.PubKey().SerializeUncompressed(),
		senderSigningPrivateKey.Serialize(),
		"USD",
		false,
		"$alice@vasp1.com",
		nil,
		nil,
		&trInfo,
		nil,
		protocol.KycStatusVerified,
		nil,
		nil,
		"/api/lnurl/utxocallback?txid=1234",
		&payeeOptions,
		nil,
	)
	require.NoError(t, err)
	client := &FakeInvoiceCreator{}
	metadata, err := createMetadataForBob()
	require.NoError(t, err)
	payeeData := protocol.PayeeData{
		"identifier": "$bob@vasp2.com",
	}
	receivingCurrencyCode := "USD"
	receivingCurrencyDecimals := 2
	fee := int64(100_000)
	conversionRate := float64(24_150)
	utxoCallback := "/api/lnurl/utxocallback?txid=1234"
	payeeIdentifier := "$bob@vasp2.com"
	serializedPrivateKey := receiverSigningPrivateKey.Serialize()
	payreqResponse, err := uma.GetPayReqResponse(
		*payreq,
		client,
		metadata,
		&receivingCurrencyCode,
		&receivingCurrencyDecimals,
		&conversionRate,
		&fee,
		&[]string{"abcdef12345"},
		nil,
		&utxoCallback,
		&payeeData,
		&serializedPrivateKey,
		&payeeIdentifier,
		nil,
		nil,
	)
	require.NoError(t, err)
	expectedAmount := int64(math.Round(float64(payreq.Amount-fee) / conversionRate))
	require.Equal(t, payreqResponse.PaymentInfo.Amount, expectedAmount)
	require.Equal(t, payreqResponse.PaymentInfo.CurrencyCode, *payreq.ReceivingCurrencyCode)

	payreqResponseJson, err := json.Marshal(payreqResponse)
	require.NoError(t, err)

	parsedResponse, err := uma.ParsePayReqResponse(payreqResponseJson)
	require.NoError(t, err)
	require.Equal(t, payreqResponse, parsedResponse)

	err = uma.VerifyPayReqResponseSignature(
		parsedResponse,
		receiverSigningPrivateKey.PubKey().SerializeUncompressed(),
		getNonceCache(),
		"$alice@vasp1.com",
		"$bob@vasp2.com",
	)
	require.NoError(t, err)
}

func TestSignAndVerifyPostTransactionCallback(t *testing.T) {
	signingPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	callback, err := uma.GetPostTransactionCallback(
		[]protocol.UtxoWithAmount{{Utxo: "abcdef12345", Amount: 1000}},
		"my-vasp.com",
		signingPrivateKey.Serialize(),
	)
	require.NoError(t, err)
	callbackJson, err := json.Marshal(callback)
	require.NoError(t, err)
	parsedCallback, err := uma.ParsePostTransactionCallback(callbackJson)
	require.NoError(t, err)
	err = uma.VerifyPostTransactionCallbackSignature(parsedCallback, signingPrivateKey.PubKey().SerializeUncompressed(), getNonceCache())
	require.NoError(t, err)
}

func TestParsePayReqFromQueryParamsNoOptionalFields(t *testing.T) {
	amount := "1000"
	params := url.Values{
		"amount": {amount},
	}
	payreq, err := uma.ParsePayRequestFromQueryParams(params)
	require.NoError(t, err)
	require.Equal(t, payreq.Amount, int64(1000))
	require.Nil(t, payreq.ReceivingCurrencyCode)
}

func TestParsePayReqFromQueryParamsAllOptionalFields(t *testing.T) {
	amount := "1000.USD"
	payerData := protocol.PayerData{
		"identifier": "$bob@vasp.com",
	}
	encodedPayerData, err := json.Marshal(payerData)
	require.NoError(t, err)
	payeeData := protocol.CounterPartyDataOptions{
		"identifier": protocol.CounterPartyDataOption{
			Mandatory: true,
		},
		"name": protocol.CounterPartyDataOption{
			Mandatory: false,
		},
	}
	encodedPayeeData, err := json.Marshal(payeeData)
	require.NoError(t, err)
	params := url.Values{
		"amount":    {amount},
		"convert":   {"USD"},
		"payerData": {string(encodedPayerData)},
		"payeeData": {string(encodedPayeeData)},
		"comment":   {"This is a comment"},
	}
	payreq, err := uma.ParsePayRequestFromQueryParams(params)
	require.NoError(t, err)
	require.Equal(t, payreq.Amount, int64(1000))
	require.Equal(t, *payreq.ReceivingCurrencyCode, "USD")
	require.Equal(t, *payreq.PayerData, payerData)
	require.Equal(t, *payreq.RequestedPayeeData, payeeData)
	require.Equal(t, *payreq.Comment, "This is a comment")
	require.Equal(t, *payreq.SendingAmountCurrencyCode, "USD")
}

func TestParseAndEncodePayReqToQueryParams(t *testing.T) {
	amount := "1000.USD"
	payerData := protocol.PayerData{
		"identifier": "$bob@vasp.com",
	}
	encodedPayerData, err := json.Marshal(payerData)
	require.NoError(t, err)
	payeeData := protocol.CounterPartyDataOptions{
		"identifier": protocol.CounterPartyDataOption{
			Mandatory: true,
		},
		"name": protocol.CounterPartyDataOption{
			Mandatory: false,
		},
	}
	encodedPayeeData, err := json.Marshal(payeeData)
	require.NoError(t, err)
	params := url.Values{
		"amount":    {amount},
		"convert":   {"USD"},
		"payerData": {string(encodedPayerData)},
		"payeeData": {string(encodedPayeeData)},
		"comment":   {"This is a comment"},
	}
	payreq, err := uma.ParsePayRequestFromQueryParams(params)
	require.NoError(t, err)
	encodedParams, err := payreq.EncodeAsUrlParams()
	require.NoError(t, err)
	require.Equal(t, params, *encodedParams)
	payreqReparsed, err := uma.ParsePayRequestFromQueryParams(*encodedParams)
	require.NoError(t, err)
	require.Equal(t, payreq, payreqReparsed)
}

func createLnurlpRequest(t *testing.T, signingPrivateKey []byte) protocol.LnurlpRequest {
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(signingPrivateKey, "$bob@vasp2.com", "vasp1.com", true, nil)
	require.NoError(t, err)
	query, err := uma.ParseLnurlpRequest(*queryUrl)
	require.NoError(t, err)
	return *query
}

func getNonceCache() uma.NonceCache {
	oneWeekAgo := time.Now().AddDate(0, 0, -7)
	return uma.NewInMemoryNonceCache(oneWeekAgo)
}

func createMetadataForBob() (string, error) {
	metadata := [][]string{
		{"text/plain", "Pay to vasp2.com user $bob"},
		{"text/identifier", "$bob@vasp2.com"},
	}

	jsonMetadata, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}

	return string(jsonMetadata), nil
}

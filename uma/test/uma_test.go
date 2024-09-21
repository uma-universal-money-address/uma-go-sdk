package uma_test

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	eciesgo "github.com/ecies/go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uma-universal-money-address/uma-go-sdk/uma"
	umaprotocol "github.com/uma-universal-money-address/uma-go-sdk/uma/protocol"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/utils"
)

func TestParse(t *testing.T) {
	expectedTime, _ := time.Parse(time.RFC3339, "2023-07-27T22:46:08Z")
	timeSec := expectedTime.Unix()
	signature := "signature"
	isSubjectToTravelRule := true
	nonce := "12345"
	vaspDomain := "vasp1.com"
	umaVersion := "1.0"
	expectedQuery := umaprotocol.LnurlpRequest{
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

func TestInvalidUserName(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurlp/bob<>%20?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	_, err := uma.ParseLnurlpRequest(*urlObj)
	require.Error(t, err)
}

func TestIsUmaQueryValid(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	require.True(t, uma.IsUmaLnurlpQuery(*urlObj))
}

func TestIsUmaQueryMissingParams(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurlp/bob?nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	require.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	require.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	require.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&umaVersion=1.0&nonce=12345&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	require.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&umaVersion=1.0&nonce=12345&vaspDomain=vasp1.com&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	// IsSubjectToTravelRule is optional
	require.True(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true"
	urlObj, _ = url.Parse(urlString)
	require.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob"
	urlObj, _ = url.Parse(urlString)
	require.False(t, uma.IsUmaLnurlpQuery(*urlObj))
}

func TestIsUmaQueryInvalidPath(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurla/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	require.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	require.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=1.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	require.False(t, uma.IsUmaLnurlpQuery(*urlObj))
}

func TestIsUmaQueryUnsupportedVersion(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=10.0&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	assert.True(t, uma.IsUmaLnurlpQuery(*urlObj))

	// Imagine if we removed the travel rule field and nonce field in a future version:
	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&vaspDomain=vasp1.com&umaVersion=10.0&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	assert.True(t, uma.IsUmaLnurlpQuery(*urlObj))
}

func TestSignAndVerifyLnurlpRequest(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(privateKey.Serialize(), "$bob@vasp2.com", "vasp1.com", true, nil)
	require.NoError(t, err)
	query, err := uma.ParseLnurlpRequest(*queryUrl)
	require.NoError(t, err)
	require.Equal(t, *query.UmaVersion, uma.UmaProtocolVersion)
	err = uma.VerifyUmaLnurlpQuerySignature(*query.AsUmaRequest(), getPubKeyResponse(privateKey), getNonceCache())
	require.NoError(t, err)
}

func TestSignAndVerifyLnurlpRequestReplacingDomain(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(privateKey.Serialize(), "$bob@vasp3.com", "vasp1.com", true, nil)
	require.NoError(t, err)
	queryUrl.Host = "vasp2.com"
	query, err := uma.ParseLnurlpRequestWithReceiverDomain(*queryUrl, "vasp3.com")
	require.NoError(t, err)
	require.Equal(t, *query.UmaVersion, uma.UmaProtocolVersion)
	require.Equal(t, query.ReceiverAddress, "$bob@vasp3.com")
	err = uma.VerifyUmaLnurlpQuerySignature(*query.AsUmaRequest(), getPubKeyResponse(privateKey), getNonceCache())
	require.NoError(t, err)
}

func TestParseLnurlpRequestUnsupportedVersion(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	version := "1000.0"
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(privateKey.Serialize(), "$bob@vasp2.com", "vasp1.com", true, &version)
	require.NoError(t, err)
	_, err = uma.ParseLnurlpRequest(*queryUrl)
	var unsupportedVersionError uma.UnsupportedVersionError
	require.ErrorAs(t, err, &unsupportedVersionError)
	require.Equal(t, unsupportedVersionError.UnsupportedVersion, version)
	require.Equal(t, unsupportedVersionError.SupportedMajorVersions, []int{1, 0})
}

func TestSignAndVerifyLnurlpRequestInvalidSignature(t *testing.T) {
	invalidPubKeyHex := "invalid pub key"
	invalidPubKeyResponse := umaprotocol.PubKeyResponse{
		SigningCertChain:    nil,
		EncryptionCertChain: nil,
		SigningPubKeyHex:    &invalidPubKeyHex,
		EncryptionPubKeyHex: &invalidPubKeyHex,
		ExpirationTimestamp: nil,
	}
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(privateKey.Serialize(), "$bob@vasp2.com", "vasp1.com", true, nil)
	require.NoError(t, err)
	query, err := uma.ParseLnurlpRequest(*queryUrl)
	require.NoError(t, err)
	err = uma.VerifyUmaLnurlpQuerySignature(*query.AsUmaRequest(), invalidPubKeyResponse, getNonceCache())
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
	err = uma.VerifyUmaLnurlpQuerySignature(*query.AsUmaRequest(), getPubKeyResponse(privateKey), uma.NewInMemoryNonceCache(tomorrow))
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
	err = uma.VerifyUmaLnurlpQuerySignature(*query.AsUmaRequest(), getPubKeyResponse(privateKey), nonceCache)
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
	kycStatus := umaprotocol.KycStatusVerified
	response, err := uma.GetLnurlpResponse(
		request,
		"https://vasp2.com/api/lnurl/payreq/$bob",
		metadata,
		1,
		10_000_000,
		&serializedPrivateKey,
		&isSubjectToTravelRule,
		&umaprotocol.CounterPartyDataOptions{
			"name":       umaprotocol.CounterPartyDataOption{Mandatory: false},
			"email":      umaprotocol.CounterPartyDataOption{Mandatory: false},
			"compliance": umaprotocol.CounterPartyDataOption{Mandatory: true},
		},
		&[]umaprotocol.Currency{
			{
				Code:                "USD",
				Name:                "US Dollar",
				Symbol:              "$",
				MillisatoshiPerUnit: 34_150,
				Convertible: umaprotocol.ConvertibleCurrency{
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
	err = uma.VerifyUmaLnurlpResponseSignature(*response.AsUmaResponse(), getPubKeyResponse(receiverSigningPrivateKey), getNonceCache())
	require.NoError(t, err)
}

func TestPayReqCreationAndParsing(t *testing.T) {
	senderSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverEncryptionPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	trInfo := "some TR info for VASP2"
	ivmsVersion := "101.1"
	trFormat := umaprotocol.TravelRuleFormat{
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
		1,
		nil,
		nil,
		&trInfo,
		&trFormat,
		umaprotocol.KycStatusVerified,
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

	err = uma.VerifyPayReqSignature(payreq, getPubKeyResponse(senderSigningPrivateKey), getNonceCache())
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
	require.Equal(t, trInfo, string(decryptedTrInfo))
}

func TestMsatsPayReqCreationAndParsing(t *testing.T) {
	senderSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverEncryptionPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	trInfo := "some TR info for VASP2"
	ivmsVersion := "101.1"
	trFormat := umaprotocol.TravelRuleFormat{
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
		1,
		nil,
		nil,
		&trInfo,
		&trFormat,
		umaprotocol.KycStatusVerified,
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

func (f *FakeInvoiceCreator) CreateInvoice(int64, string, *string) (*string, error) {
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
	payeeOptions := umaprotocol.CounterPartyDataOptions{
		"identifier": umaprotocol.CounterPartyDataOption{
			Mandatory: true,
		},
		"name": umaprotocol.CounterPartyDataOption{
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
		1,
		nil,
		nil,
		&trInfo,
		nil,
		umaprotocol.KycStatusVerified,
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
	payeeData := umaprotocol.PayeeData{
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
	require.Equal(t, payreqResponse.PaymentInfo.Amount, &payreq.Amount)
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
		getPubKeyResponse(receiverSigningPrivateKey),
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
	payeeOptions := umaprotocol.CounterPartyDataOptions{
		"identifier": umaprotocol.CounterPartyDataOption{
			Mandatory: true,
		},
		"name": umaprotocol.CounterPartyDataOption{
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
		1,
		nil,
		nil,
		&trInfo,
		nil,
		umaprotocol.KycStatusVerified,
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
	payeeData := umaprotocol.PayeeData{
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
	require.Equal(t, payreqResponse.PaymentInfo.Amount, &expectedAmount)
	require.Equal(t, payreqResponse.PaymentInfo.CurrencyCode, *payreq.ReceivingCurrencyCode)

	payreqResponseJson, err := json.Marshal(payreqResponse)
	require.NoError(t, err)

	parsedResponse, err := uma.ParsePayReqResponse(payreqResponseJson)
	require.NoError(t, err)
	require.Equal(t, payreqResponse, parsedResponse)

	err = uma.VerifyPayReqResponseSignature(
		parsedResponse,
		getPubKeyResponse(receiverSigningPrivateKey),
		getNonceCache(),
		"$alice@vasp1.com",
		"$bob@vasp2.com",
	)
	require.NoError(t, err)
}

func TestV0PayReqResponseAndParsing(t *testing.T) {
	senderSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverEncryptionPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	trInfo := "some TR info for VASP2"
	payeeOptions := umaprotocol.CounterPartyDataOptions{
		"identifier": umaprotocol.CounterPartyDataOption{
			Mandatory: true,
		},
		"name": umaprotocol.CounterPartyDataOption{
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
		0,
		nil,
		nil,
		&trInfo,
		nil,
		umaprotocol.KycStatusVerified,
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
	payeeData := umaprotocol.PayeeData{
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
	require.Equal(t, payreqResponse.PaymentInfo.CurrencyCode, *payreq.ReceivingCurrencyCode)
	require.Equal(t, payreqResponse.PaymentInfo.Multiplier, conversionRate)
	require.Equal(t, payreqResponse.PaymentInfo.Decimals, receivingCurrencyDecimals)
	require.Equal(t, payreqResponse.PaymentInfo.ExchangeFeesMillisatoshi, fee)
	compliance, err := payreqResponse.PayeeData.Compliance()
	require.NoError(t, err)
	require.Equal(t, compliance.Utxos, []string{"abcdef12345"})

	payreqResponseJson, err := json.Marshal(payreqResponse)
	require.NoError(t, err)

	parsedResponse, err := uma.ParsePayReqResponse(payreqResponseJson)
	require.NoError(t, err)
	require.Equal(t, payreqResponse, parsedResponse)
}

func TestSignAndVerifyPostTransactionCallback(t *testing.T) {
	signingPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	callback, err := uma.GetPostTransactionCallback(
		[]umaprotocol.UtxoWithAmount{{Utxo: "abcdef12345", Amount: 1000}},
		"my-vasp.com",
		signingPrivateKey.Serialize(),
	)
	require.NoError(t, err)
	callbackJson, err := json.Marshal(callback)
	require.NoError(t, err)
	parsedCallback, err := uma.ParsePostTransactionCallback(callbackJson)
	require.NoError(t, err)
	err = uma.VerifyPostTransactionCallbackSignature(parsedCallback, getPubKeyResponse(signingPrivateKey), getNonceCache())
	require.NoError(t, err)
}

func TestParsePayReqFromQueryParamsNoOptionalFields(t *testing.T) {
	amount := "1000"
	params := url.Values{
		"amount": {amount},
	}
	payreq, err := umaprotocol.ParsePayRequestFromQueryParams(params)
	require.NoError(t, err)
	require.Equal(t, payreq.Amount, int64(1000))
	require.Nil(t, payreq.ReceivingCurrencyCode)
}

func TestParsePayReqFromQueryParamsAllOptionalFields(t *testing.T) {
	amount := "1000.USD"
	payerData := umaprotocol.PayerData{
		"identifier": "$bob@vasp.com",
	}
	encodedPayerData, err := json.Marshal(payerData)
	require.NoError(t, err)
	payeeData := umaprotocol.CounterPartyDataOptions{
		"identifier": umaprotocol.CounterPartyDataOption{
			Mandatory: true,
		},
		"name": umaprotocol.CounterPartyDataOption{
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
	payreq, err := umaprotocol.ParsePayRequestFromQueryParams(params)
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
	payerData := umaprotocol.PayerData{
		"identifier": "$bob@vasp.com",
	}
	encodedPayerData, err := json.Marshal(payerData)
	require.NoError(t, err)
	payeeData := umaprotocol.CounterPartyDataOptions{
		"identifier": umaprotocol.CounterPartyDataOption{
			Mandatory: true,
		},
		"name": umaprotocol.CounterPartyDataOption{
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
	payreq, err := umaprotocol.ParsePayRequestFromQueryParams(params)
	require.NoError(t, err)
	encodedParams, err := payreq.EncodeAsUrlParams()
	require.NoError(t, err)
	require.Equal(t, params, *encodedParams)
	payreqReparsed, err := umaprotocol.ParsePayRequestFromQueryParams(*encodedParams)
	require.NoError(t, err)
	require.Equal(t, payreq, payreqReparsed)
}

func TestCertificateUtils(t *testing.T) {
	pemCert := `-----BEGIN CERTIFICATE-----
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
	pubkey, err := utils.ExtractPubkeyFromPemCertificateChain(&pemCert)
	require.NoError(t, err)

	publicKeyBytes := pubkey.SerializeUncompressed()
	expectedPublicKey, err := hex.DecodeString("04419c5467ea563f0010fd614f85e885ac99c21b8e8d416241175fdd5efd2244fe907e2e6fa3dd6631b1b17cd28798da8d882a34c4776d44cc4090781c7aadea1b")
	require.NoError(t, err)
	require.Equal(t, publicKeyBytes, expectedPublicKey)

	hexDerCerts, err := utils.ConvertPemCertificateChainToHexEncodedDer(&pemCert)
	require.NoError(t, err)
	require.Len(t, hexDerCerts, 2)
	newPemCert, err := utils.ConvertHexEncodedDerToPemCertChain(&hexDerCerts)
	require.NoError(t, err)
	require.Equal(t, *newPemCert, pemCert)
}

func createLnurlpRequest(t *testing.T, signingPrivateKey []byte) umaprotocol.LnurlpRequest {
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

func getPubKeyResponse(privateKey *secp256k1.PrivateKey) umaprotocol.PubKeyResponse {
	pubKey := hex.EncodeToString(privateKey.PubKey().SerializeUncompressed())
	return umaprotocol.PubKeyResponse{
		SigningCertChain:    nil,
		EncryptionCertChain: nil,
		SigningPubKeyHex:    &pubKey,
		EncryptionPubKeyHex: &pubKey,
		ExpirationTimestamp: nil,
	}
}

func TestUMAInvoice(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	kyc := umaprotocol.KycStatusVerified
	umaInvoice, err := uma.CreateUmaInvoice(
		"$foo@bar.com",
		100000,
		umaprotocol.InvoiceCurrency{
			Code:     "USD",
			Name:     "US Dollar",
			Symbol:   "$",
			Decimals: 2,
		},
		1721081249,
		"https://vasp2.com/api/lnurl/payreq/$foo",
		true,
		&umaprotocol.CounterPartyDataOptions{
			"name":       umaprotocol.CounterPartyDataOption{Mandatory: false},
			"email":      umaprotocol.CounterPartyDataOption{Mandatory: false},
			"compliance": umaprotocol.CounterPartyDataOption{Mandatory: true},
		},
		nil,
		&kyc,
		nil,
		nil,
		privateKey.Serialize(),
	)
	require.NoError(t, err)

	encodedInvoice, err := umaInvoice.ToBech32String()
	require.NoError(t, err)

	decodedInvoice, err := uma.DecodeUmaInvoice(encodedInvoice)
	require.NoError(t, err)
	require.Equal(t, decodedInvoice.ReceiverUma, "$foo@bar.com")
	require.Equal(t, decodedInvoice.Amount, uint64(100000))
	require.Equal(t, decodedInvoice.ReceivingCurrency.Code, "USD")
	require.Equal(t, decodedInvoice.ReceivingCurrency.Name, "US Dollar")
	require.Equal(t, decodedInvoice.ReceivingCurrency.Symbol, "$")
	require.Equal(t, decodedInvoice.Expiration, uint64(1721081249))
	require.Equal(t, decodedInvoice.Callback, "https://vasp2.com/api/lnurl/payreq/$foo")
	require.Equal(t, decodedInvoice.IsSubjectToTravelRule, true)
	require.Equal(t, *decodedInvoice.RequiredPayerData, umaprotocol.CounterPartyDataOptions{
		"name":       umaprotocol.CounterPartyDataOption{Mandatory: false},
		"email":      umaprotocol.CounterPartyDataOption{Mandatory: false},
		"compliance": umaprotocol.CounterPartyDataOption{Mandatory: true},
	})
	require.Equal(t, *decodedInvoice.KycStatus, umaprotocol.KycStatusVerified)

	publicKeyResponse := getPubKeyResponse(privateKey)
	err = uma.VerifyUmaInvoiceSignature(*decodedInvoice, publicKeyResponse)
	require.NoError(t, err)
}

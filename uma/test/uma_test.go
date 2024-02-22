package uma_test

import (
	"encoding/hex"
	"encoding/json"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	eciesgo "github.com/ecies/go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uma-universal-money-address/uma-go-sdk/uma"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	expectedTime, _ := time.Parse(time.RFC3339, "2023-07-27T22:46:08Z")
	timeSec := expectedTime.Unix()
	expectedQuery := uma.LnurlpRequest{
		ReceiverAddress:       "bob@vasp2.com",
		Signature:             "signature",
		IsSubjectToTravelRule: true,
		Nonce:                 "12345",
		Timestamp:             expectedTime,
		VaspDomain:            "vasp1.com",
		UmaVersion:            "0.1",
	}
	urlString := "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=0.1&isSubjectToTravelRule=true&timestamp=" + strconv.FormatInt(timeSec, 10)
	urlObj, _ := url.Parse(urlString)
	query, err := uma.ParseLnurlpRequest(*urlObj)
	if err != nil || query == nil {
		t.Fatalf("Parse(%s) failed: %s", urlObj, err)
	}
	assert.ObjectsAreEqual(expectedQuery, *query)
}

func TestIsUmaQueryValid(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=0.1&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	assert.True(t, uma.IsUmaLnurlpQuery(*urlObj))
}

func TestIsUmaQueryMissingParams(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurlp/bob?nonce=12345&vaspDomain=vasp1.com&umaVersion=0.1&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&vaspDomain=vasp1.com&umaVersion=0.1&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&umaVersion=0.1&nonce=12345&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&umaVersion=0.1&nonce=12345&vaspDomain=vasp1.com&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	// IsSubjectToTravelRule is optional
	assert.True(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=0.1&isSubjectToTravelRule=true"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/.well-known/lnurlp/bob"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))
}

func TestIsUmaQueryInvalidPath(t *testing.T) {
	urlString := "https://vasp2.com/.well-known/lnurla/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=0.1&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ := url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/bob?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=0.1&isSubjectToTravelRule=true&timestamp=12345678"
	urlObj, _ = url.Parse(urlString)
	assert.False(t, uma.IsUmaLnurlpQuery(*urlObj))

	urlString = "https://vasp2.com/?signature=signature&nonce=12345&vaspDomain=vasp1.com&umaVersion=0.1&isSubjectToTravelRule=true&timestamp=12345678"
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
	assert.Equal(t, query.UmaVersion, uma.UmaProtocolVersion)
	err = uma.VerifyUmaLnurlpQuerySignature(query, privateKey.PubKey().SerializeUncompressed(), getNonceCache())
	require.NoError(t, err)
}

func TestSignAndVerifyLnurlpRequestInvalidSignature(t *testing.T) {
	privateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(privateKey.Serialize(), "$bob@vasp2.com", "vasp1.com", true, nil)
	require.NoError(t, err)
	query, err := uma.ParseLnurlpRequest(*queryUrl)
	require.NoError(t, err)
	err = uma.VerifyUmaLnurlpQuerySignature(query, []byte("invalid pub key"), getNonceCache())
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
	err = uma.VerifyUmaLnurlpQuerySignature(query, privateKey.PubKey().SerializeUncompressed(), uma.NewInMemoryNonceCache(tomorrow))
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
	err = nonceCache.CheckAndSaveNonce(query.Nonce, query.Timestamp)
	require.NoError(t, err)
	err = uma.VerifyUmaLnurlpQuerySignature(query, privateKey.PubKey().SerializeUncompressed(), nonceCache)
	require.Error(t, err)
}

func TestSignAndVerifyLnurlpResponse(t *testing.T) {
	senderSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	request := createLnurlpRequest(t, senderSigningPrivateKey.Serialize())
	metadata, err := createMetadataForBob()
	require.NoError(t, err)
	response, err := uma.GetLnurlpResponse(
		request,
		receiverSigningPrivateKey.Serialize(),
		true,
		"https://vasp2.com/api/lnurl/payreq/$bob",
		metadata,
		1,
		10_000_000,
		uma.CounterPartyDataOptions{
			"name":       uma.CounterPartyDataOption{Mandatory: false},
			"email":      uma.CounterPartyDataOption{Mandatory: false},
			"compliance": uma.CounterPartyDataOption{Mandatory: true},
		},
		[]uma.Currency{
			{
				Code:                "USD",
				Name:                "US Dollar",
				Symbol:              "$",
				MillisatoshiPerUnit: 34_150,
				MinSendable:         1,
				MaxSendable:         10_000_000,
				Decimals:            2,
			},
		},
		uma.KycStatusVerified,
	)
	require.NoError(t, err)
	responseJson, err := json.Marshal(response)
	require.NoError(t, err)

	response, err = uma.ParseLnurlpResponse(responseJson)
	require.NoError(t, err)
	err = uma.VerifyUmaLnurlpResponseSignature(response, receiverSigningPrivateKey.PubKey().SerializeUncompressed(), getNonceCache())
	require.NoError(t, err)
}

func TestPayReqCreationAndParsing(t *testing.T) {
	senderSigningPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)
	receiverEncryptionPrivateKey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	trInfo := "some TR info for VASP2"
	ivmsVersion := "101.1"
	trFormat := uma.TravelRuleFormat{
		Type:    "IVMS",
		Version: &ivmsVersion,
	}
	payreq, err := uma.GetPayRequest(
		receiverEncryptionPrivateKey.PubKey().SerializeUncompressed(),
		senderSigningPrivateKey.Serialize(),
		"USD",
		1000,
		"$alice@vasp1.com",
		nil,
		nil,
		&trInfo,
		&trFormat,
		uma.KycStatusVerified,
		nil,
		nil,
		"/api/lnurl/utxocallback?txid=1234",
		nil,
	)
	require.NoError(t, err)

	payreqJson, err := json.Marshal(payreq)
	require.NoError(t, err)

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

type FakeInvoiceCreator struct{}

func (f *FakeInvoiceCreator) CreateUmaInvoice(int64, string) (*string, error) {
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
	payeeOptions := uma.CounterPartyDataOptions{
		"identifier": uma.CounterPartyDataOption{
			Mandatory: true,
		},
		"name": uma.CounterPartyDataOption{
			Mandatory: false,
		},
	}
	payreq, err := uma.GetPayRequest(
		receiverEncryptionPrivateKey.PubKey().SerializeUncompressed(),
		senderSigningPrivateKey.Serialize(),
		"USD",
		1000,
		"$alice@vasp1.com",
		nil,
		nil,
		&trInfo,
		nil,
		uma.KycStatusVerified,
		nil,
		nil,
		"/api/lnurl/utxocallback?txid=1234",
		&payeeOptions,
	)
	require.NoError(t, err)
	client := &FakeInvoiceCreator{}
	metadata, err := createMetadataForBob()
	require.NoError(t, err)
	payeeData := uma.PayeeData{
		"identifier": "$bob@vasp2.com",
	}
	payreqResponse, err := uma.GetPayReqResponse(
		payreq,
		client,
		metadata,
		"USD",
		2,
		24_150,
		100_000,
		[]string{"abcdef12345"},
		nil,
		"/api/lnurl/utxocallback?txid=1234",
		&payeeData,
		receiverSigningPrivateKey.Serialize(),
		"$bob@vasp2.com",
	)
	require.NoError(t, err)

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

func createLnurlpRequest(t *testing.T, signingPrivateKey []byte) *uma.LnurlpRequest {
	queryUrl, err := uma.GetSignedLnurlpRequestUrl(signingPrivateKey, "$bob@vasp2.com", "vasp1.com", true, nil)
	require.NoError(t, err)
	query, err := uma.ParseLnurlpRequest(*queryUrl)
	require.NoError(t, err)
	return query
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

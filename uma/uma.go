package uma

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	umacrypto "github.com/uma-universal-money-address/uma-crypto-uniffi/uma-crypto-go"
)

// FetchPublicKeyForVasp fetches the public key for another VASP.
//
// If the public key is not in the cache, it will be fetched from the VASP's domain.
// The public key will be cached for future use.
//
// NOTE: localhost domains will be fetched over HTTP for testing purposes, all other
// domains will be fetched over HTTPS.
//
// Args:
//
//	vaspDomain: the domain of the VASP.
//	cache: the PublicKeyCache cache to use. You can use the InMemoryPublicKeyCache struct, or implement your own persistent cache with any storage type.
func FetchPublicKeyForVasp(vaspDomain string, cache PublicKeyCache) (*PubKeyResponse, error) {
	publicKey := cache.FetchPublicKeyForVasp(vaspDomain)
	if publicKey != nil {
		return publicKey, nil
	}

	scheme := "https://"
	if strings.HasPrefix(vaspDomain, "localhost:") {
		scheme = "http://"
	}
	resp, err := http.Get(scheme + vaspDomain + "/.well-known/lnurlpubkey")
	if err != nil {
		return nil, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)

	if resp.StatusCode != 200 {
		return nil, errors.New("invalid response from VASP")
	}

	responseBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var pubKeyResponse PubKeyResponse
	err = json.Unmarshal(responseBodyBytes, &pubKeyResponse)
	if err != nil {
		return nil, err
	}

	cache.AddPublicKeyForVasp(vaspDomain, &pubKeyResponse)
	return &pubKeyResponse, nil
}

func GenerateNonce() (*string, error) {
	randomBigInt, err := rand.Int(rand.Reader, big.NewInt(0xFFFFFFFF))
	if err != nil {
		return nil, err
	}
	nonce := strconv.FormatUint(randomBigInt.Uint64(), 10)
	return &nonce, nil
}

func signPayload(payload []byte, privateKeyBytes []byte) (*string, error) {
	signature, err := umacrypto.SignEcdsa(payload, privateKeyBytes)
	if err != nil {
		return nil, err
	}
	signatureString := hex.EncodeToString(signature)
	return &signatureString, nil
}

// VerifyPayReqSignature Verifies the signature on an uma pay request based on the public key of the VASP making the
// request.
//
// Args:
//
//	query: the signed query to verify.
//	otherVaspPubKey: the bytes of the signing public key of the VASP making this request.
func VerifyPayReqSignature(query *PayRequest, otherVaspPubKey []byte) error {
	return verifySignature(query.signablePayload(), query.PayerData.Compliance.Signature, otherVaspPubKey)
}

// verifySignature Verifies the signature of the uma request.
//
// Args:
//
//	payload: the payload that was signed.
//	signature: the hex-encoded signature.
//	otherVaspPubKey: the bytes of the signing public key of the VASP who signed the payload.
func verifySignature(payload []byte, signature string, otherVaspPubKey []byte) error {
	decodedSignature, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}
	verified, err := umacrypto.VerifyEcdsa(payload, decodedSignature, otherVaspPubKey)
	if err != nil {
		return err
	}
	if !verified {
		return errors.New("invalid uma signature")
	}

	return nil
}

// GetSignedLnurlpRequestUrl Creates a signed uma request URL.
//
// Args:
//
//	signingPrivateKey: the private key of the VASP that is sending the payment. This will be used to sign the request.
//	receiverAddress: the address of the receiver of the payment (i.e. $bob@vasp2).
//	senderVaspDomain: the domain of the VASP that is sending the payment. It will be used by the receiver to fetch the public keys of the sender.
//	isSubjectToTravelRule: whether the sending VASP is a financial institution that requires travel rule information.
//	umaVersionOverride: the version of the UMA protocol to use. If not specified, the latest version will be used.
func GetSignedLnurlpRequestUrl(
	signingPrivateKey []byte,
	receiverAddress string,
	senderVaspDomain string,
	isSubjectToTravelRule bool,
	umaVersionOverride *string,
) (*url.URL, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	umaVersion := UmaProtocolVersion
	if umaVersionOverride != nil {
		umaVersion = *umaVersionOverride
	}
	unsignedRequest := LnurlpRequest{
		ReceiverAddress:       receiverAddress,
		IsSubjectToTravelRule: isSubjectToTravelRule,
		VaspDomain:            senderVaspDomain,
		Timestamp:             time.Now(),
		Nonce:                 *nonce,
		UmaVersion:            umaVersion,
	}
	signature, err := signPayload(unsignedRequest.signablePayload(), signingPrivateKey)
	if err != nil {
		return nil, err
	}
	unsignedRequest.Signature = *signature

	return unsignedRequest.EncodeToUrl()
}

// IsUmaLnurlpQuery Checks if the given URL is a valid UMA request. If this returns false,
// You should try to process the request as a regular LNURLp request to fall back to LNURL-PAY.
func IsUmaLnurlpQuery(url url.URL) bool {
	query, err := ParseLnurlpRequest(url)
	return err == nil && query != nil
}

// ParseLnurlpRequest Parse Parses the message into an LnurlpRequest object.
// Args:
//
//	url: the full URL of the uma request.
func ParseLnurlpRequest(url url.URL) (*LnurlpRequest, error) {
	query := url.Query()
	signature := query.Get("signature")
	vaspDomain := query.Get("vaspDomain")
	nonce := query.Get("nonce")
	isSubjectToTravelRule := query.Get("isSubjectToTravelRule")
	umaVersion := query.Get("umaVersion")
	timestamp := query.Get("timestamp")
	timestampAsString, dateErr := strconv.ParseInt(timestamp, 10, 64)
	if dateErr != nil {
		return nil, errors.New("invalid timestamp")
	}
	timestampAsTime := time.Unix(timestampAsString, 0)

	if vaspDomain == "" || signature == "" || nonce == "" || timestamp == "" || umaVersion == "" {
		return nil, errors.New("missing uma query parameters. vaspDomain, umaVersion, signature, nonce, and timestamp are required")
	}

	pathParts := strings.Split(url.Path, "/")
	if len(pathParts) != 4 || pathParts[1] != ".well-known" || pathParts[2] != "lnurlp" {
		return nil, errors.New("invalid uma request path")
	}
	receiverAddress := pathParts[3] + "@" + url.Host

	if !IsVersionSupported(umaVersion) {
		return nil, UnsupportedVersionError{}
	}

	return &LnurlpRequest{
		VaspDomain:            vaspDomain,
		UmaVersion:            umaVersion,
		Signature:             signature,
		ReceiverAddress:       receiverAddress,
		Nonce:                 nonce,
		Timestamp:             timestampAsTime,
		IsSubjectToTravelRule: strings.ToLower(isSubjectToTravelRule) == "true",
	}, nil
}

// VerifyUmaLnurlpQuerySignature Verifies the signature on an uma Lnurlp query based on the public key of the VASP making the request.
//
// Args:
//
//	query: the signed query to verify.
//	otherVaspSigningPubKey: the public key of the VASP making this request in bytes.
func VerifyUmaLnurlpQuerySignature(query *LnurlpRequest, otherVaspSigningPubKey []byte) error {
	return verifySignature(query.signablePayload(), query.Signature, otherVaspSigningPubKey)
}

func GetLnurlpResponse(
	request *LnurlpRequest,
	privateKeyBytes []byte,
	requiresTravelRuleInfo bool,
	callback string,
	encodedMetadata string,
	minSendableSats int64,
	maxSendableSats int64,
	payerDataOptions PayerDataOptions,
	currencyOptions []Currency,
	receiverKycStatus KycStatus,
) (*LnurlpResponse, error) {
	umaVersion, err := SelectLowerVersion(request.UmaVersion, UmaProtocolVersion)
	if err != nil {
		return nil, err
	}

	complianceResponse, err := getSignedLnurlpComplianceResponse(request, privateKeyBytes, requiresTravelRuleInfo, receiverKycStatus)
	if err != nil {
		return nil, err
	}

	return &LnurlpResponse{
		Tag:               "payRequest",
		Callback:          callback,
		MinSendable:       minSendableSats,
		MaxSendable:       maxSendableSats,
		EncodedMetadata:   encodedMetadata,
		Currencies:        currencyOptions,
		RequiredPayerData: payerDataOptions,
		Compliance:        *complianceResponse,
		UmaVersion:        *umaVersion,
	}, nil
}

func getSignedLnurlpComplianceResponse(
	query *LnurlpRequest,
	privateKeyBytes []byte,
	isSubjectToTravelRule bool,
	receiverKycStatus KycStatus,
) (*LnurlComplianceResponse, error) {
	timestamp := time.Now().Unix()
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	payloadString := strings.Join([]string{query.ReceiverAddress, *nonce, strconv.FormatInt(timestamp, 10)}, "|")
	signature, err := signPayload([]byte(payloadString), privateKeyBytes)
	if err != nil {
		return nil, err
	}
	return &LnurlComplianceResponse{
		KycStatus:             receiverKycStatus,
		Signature:             *signature,
		Nonce:                 *nonce,
		Timestamp:             timestamp,
		IsSubjectToTravelRule: isSubjectToTravelRule,
		ReceiverIdentifier:    query.ReceiverAddress,
	}, nil
}

// VerifyUmaLnurlpResponseSignature Verifies the signature on an uma Lnurlp response based on the public key of the VASP making the request.
//
// Args:
//
//	response: the signed response to verify.
//	otherVaspSigningPubKey: the public key of the VASP making this request in bytes.
func VerifyUmaLnurlpResponseSignature(response *LnurlpResponse, otherVaspSigningPubKey []byte) error {
	return verifySignature(response.signablePayload(), response.Compliance.Signature, otherVaspSigningPubKey)
}

func ParseLnurlpResponse(bytes []byte) (*LnurlpResponse, error) {
	var response LnurlpResponse
	err := json.Unmarshal(bytes, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// GetVaspDomainFromUmaAddress Gets the domain of the VASP from an uma address.
func GetVaspDomainFromUmaAddress(umaAddress string) (string, error) {
	addressParts := strings.Split(umaAddress, "@")
	if len(addressParts) != 2 {
		return "", errors.New("invalid uma address")
	}
	return addressParts[1], nil
}

// GetPayRequest Creates a signed uma pay request.
//
// Args:
//
//		receiverEncryptionPubKey: the public key of the receiver that will be used to encrypt the travel rule information.
//		sendingVaspPrivateKey: the private key of the VASP that is sending the payment. This will be used to sign the request.
//		currencyCode: the code of the currency that the receiver will receive for this payment.
//		amount: the amount of the payment in the smallest unit of the specified currency (i.e. cents for USD).
//		payerIdentifier: the identifier of the sender. For example, $alice@vasp1.com
//		payerName: the name of the sender (optional).
//		payerEmail: the email of the sender (optional).
//		trInfo: the travel rule information. This will be encrypted before sending to the receiver.
//		trInfoFormat: the standardized format of the travel rule information (e.g. IVMS). Null indicates raw json or a custom format, or no travel rule information.
//		isPayerKYCd: whether the sender is a KYC'd customer of the sending VASP.
//		payerUtxos: the list of UTXOs of the sender's channels that might be used to fund the payment.
//	 	payerNodePubKey: If known, the public key of the sender's node. If supported by the receiving VASP's compliance provider,
//	        this will be used to pre-screen the sender's UTXOs for compliance purposes.
//		utxoCallback: the URL that the receiver will call to send UTXOs of the channel that the receiver used to receive the payment once it completes.
func GetPayRequest(
	receiverEncryptionPubKey []byte,
	sendingVaspPrivateKey []byte,
	currencyCode string,
	amount int64,
	payerIdentifier string,
	payerName *string,
	payerEmail *string,
	trInfo *string,
	trInfoFormat *TravelRuleFormat,
	payerKycStatus KycStatus,
	payerUtxos *[]string,
	payerNodePubKey *string,
	utxoCallback string,
) (*PayRequest, error) {
	complianceData, err := getSignedCompliancePayerData(
		receiverEncryptionPubKey,
		sendingVaspPrivateKey,
		payerIdentifier,
		trInfo,
		trInfoFormat,
		payerKycStatus,
		payerUtxos,
		payerNodePubKey,
		utxoCallback,
	)
	if err != nil {
		return nil, err
	}

	return &PayRequest{
		CurrencyCode: currencyCode,
		Amount:       amount,
		PayerData: PayerData{
			Name:       payerName,
			Email:      payerEmail,
			Identifier: payerIdentifier,
			Compliance: complianceData,
		},
	}, nil
}

func getSignedCompliancePayerData(
	receiverEncryptionPubKeyBytes []byte,
	sendingVaspPrivateKeyBytes []byte,
	payerIdentifier string,
	trInfo *string,
	trInfoFormat *TravelRuleFormat,
	payerKycStatus KycStatus,
	payerUtxos *[]string,
	payerNodePubKey *string,
	utxoCallback string,
) (*CompliancePayerData, error) {
	timestamp := time.Now().Unix()
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	var encryptedTrInfo *string
	if trInfo != nil {
		encryptedTrInfo, err = encryptTrInfo(*trInfo, receiverEncryptionPubKeyBytes)
		if err != nil {
			return nil, err
		}
	}
	payloadString := strings.Join([]string{payerIdentifier, *nonce, strconv.FormatInt(timestamp, 10)}, "|")
	signature, err := signPayload([]byte(payloadString), sendingVaspPrivateKeyBytes)
	if err != nil {
		return nil, err
	}

	return &CompliancePayerData{
		EncryptedTravelRuleInfo: encryptedTrInfo,
		TravelRuleFormat:        trInfoFormat,
		KycStatus:               payerKycStatus,
		Utxos:                   payerUtxos,
		NodePubKey:              payerNodePubKey,
		UtxoCallback:            utxoCallback,
		SignatureNonce:          *nonce,
		SignatureTimestamp:      timestamp,
		Signature:               *signature,
	}, nil
}

func encryptTrInfo(trInfo string, receiverEncryptionPubKey []byte) (*string, error) {
	encryptedTrInfoBytes, err := umacrypto.EncryptEcies([]byte(trInfo), receiverEncryptionPubKey)
	if err != nil {
		return nil, err
	}

	encryptedTrInfoHex := hex.EncodeToString(encryptedTrInfoBytes)
	return &encryptedTrInfoHex, nil
}

func ParsePayRequest(bytes []byte) (*PayRequest, error) {
	var response PayRequest
	err := json.Unmarshal(bytes, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

type UmaInvoiceCreator interface {
	CreateUmaInvoice(amountMsats int64, metadata string) (*string, error)
}

// GetPayReqResponse Creates an uma pay request response with an encoded invoice.
//
// Args:
//
//		query: the uma pay request.
//		invoiceCreator: the object that will create the invoice.
//		metadata: the metadata that will be added to the invoice's metadata hash field. Note that this should not include
//		    the extra payer data. That will be appended automatically.
//		currencyCode: the code of the currency that the receiver will receive for this payment.
//		conversionRate: milli-satoshis per the smallest unit of the specified currency. This rate is committed to by the
//	    	receiving VASP until the invoice expires.
//		receiverFeesMillisats: the fees charged (in millisats) by the receiving VASP to convert to the target currency.
//		    This is separate from the conversion rate.
//		receiverChannelUtxos: the list of UTXOs of the receiver's channels that might be used to fund the payment.
//		receiverNodePubKey: If known, the public key of the receiver's node. If supported by the sending VASP's compliance provider,
//	        this will be used to pre-screen the receiver's UTXOs for compliance purposes.
//		utxoCallback: the URL that the receiving VASP will call to send UTXOs of the channel that the receiver used to
//	    	receive the payment once it completes.
func GetPayReqResponse(
	query *PayRequest,
	invoiceCreator UmaInvoiceCreator,
	metadata string,
	currencyCode string,
	conversionRate int64,
	receiverFeesMillisats int64,
	receiverChannelUtxos []string,
	receiverNodePubKey *string,
	utxoCallback string,
) (*PayReqResponse, error) {
	msatsAmount := query.Amount*conversionRate + receiverFeesMillisats
	encodedPayerData, err := json.Marshal(query.PayerData)
	if err != nil {
		return nil, err
	}
	encodedInvoice, err := invoiceCreator.CreateUmaInvoice(msatsAmount, metadata+"{"+string(encodedPayerData)+"}")
	if err != nil {
		return nil, err
	}
	return &PayReqResponse{
		EncodedInvoice: *encodedInvoice,
		Routes:         []Route{},
		Compliance: PayReqResponseCompliance{
			Utxos:        receiverChannelUtxos,
			NodePubKey:   receiverNodePubKey,
			UtxoCallback: utxoCallback,
		},
		PaymentInfo: PayReqResponsePaymentInfo{
			CurrencyCode:             currencyCode,
			Multiplier:               conversionRate,
			ExchangeFeesMillisatoshi: receiverFeesMillisats,
		},
	}, nil
}

// ParsePayReqResponse Parses the uma pay request response from a raw response body.
func ParsePayReqResponse(bytes []byte) (*PayReqResponse, error) {
	var response PayReqResponse
	err := json.Unmarshal(bytes, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

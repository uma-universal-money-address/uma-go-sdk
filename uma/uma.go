package uma

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	eciesgo "github.com/ecies/go/v2"
	"github.com/google/uuid"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/protocol"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/utils"
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
func FetchPublicKeyForVasp(vaspDomain string, cache PublicKeyCache) (*protocol.PubKeyResponse, error) {
	publicKey := cache.FetchPublicKeyForVasp(vaspDomain)
	if publicKey != nil {
		return publicKey, nil
	}

	scheme := "https://"
	if utils.IsDomainLocalhost(vaspDomain) {
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

	var pubKeyResponse protocol.PubKeyResponse
	err = json.Unmarshal(responseBodyBytes, &pubKeyResponse)
	if err != nil {
		return nil, err
	}

	cache.AddPublicKeyForVasp(vaspDomain, &pubKeyResponse)
	return &pubKeyResponse, nil
}

// GetPubKeyResponse Creates a public key response to be shared with the counterparty VASP.
//
// Args:
//
//	signingCertChainPem: The PEM-encoded certificate chain used to verify signatures from a VASP.
//	encryptionCertChainPem: The PEM-encoded certificate chain used to encrypt TR info sent to a VASP.
//	expirationTimestamp: Seconds since epoch at which these pub keys must be refreshed. It can be safely cached until this expiration (or forever if null).
func GetPubKeyResponse(
	signingCertChainPem string,
	encryptionCertChainPem string,
	expirationTimestamp *int64,
) (*protocol.PubKeyResponse, error) {
	signingPubKey, err := utils.ExtractPubkeyFromPemCertificateChain(&signingCertChainPem)
	if err != nil {
		return nil, err
	}
	encryptionPubKey, err := utils.ExtractPubkeyFromPemCertificateChain(&encryptionCertChainPem)
	if err != nil {
		return nil, err
	}
	signingPubKeyHex := hex.EncodeToString(signingPubKey.SerializeUncompressed())
	encryptionPubKeyHex := hex.EncodeToString(encryptionPubKey.SerializeUncompressed())
	return &protocol.PubKeyResponse{
		SigningCertChain:    &signingCertChainPem,
		EncryptionCertChain: &encryptionCertChainPem,
		SigningPubKeyHex:    &signingPubKeyHex,
		EncryptionPubKeyHex: &encryptionPubKeyHex,
		ExpirationTimestamp: expirationTimestamp,
	}, nil
}

func GenerateNonce() (*string, error) {
	randomBigInt, err := rand.Int(rand.Reader, big.NewInt(0xFFFFFFFF))
	if err != nil {
		return nil, err
	}
	nonce := strconv.FormatUint(randomBigInt.Uint64(), 10)
	return &nonce, nil
}

func signPayloadToBytes(payload []byte, privateKeyBytes []byte) ([]byte, error) {
	privateKey := secp256k1.PrivKeyFromBytes(privateKeyBytes)
	hash := crypto.SHA256.New()
	_, err := hash.Write(payload)
	if err != nil {
		return nil, err
	}
	hashedPayload := hash.Sum(nil)
	signature, err := privateKey.ToECDSA().Sign(rand.Reader, hashedPayload, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func signPayload(payload []byte, privateKeyBytes []byte) (*string, error) {
	signature, err := signPayloadToBytes(payload, privateKeyBytes)
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
//	otherVaspPubKeyResponse: the PubKeyResponse of the VASP making this request.
//	nonceCache: the NonceCache cache to use to prevent replay attacks.
func VerifyPayReqSignature(query *protocol.PayRequest, otherVaspPubKeyResponse protocol.PubKeyResponse, nonceCache NonceCache) error {
	complianceData, err := query.PayerData.Compliance()
	if err != nil {
		return err
	}
	if complianceData == nil {
		return errors.New("missing compliance data")
	}
	err = nonceCache.CheckAndSaveNonce(
		complianceData.SignatureNonce,
		time.Unix(complianceData.SignatureTimestamp, 0),
	)
	if err != nil {
		return err
	}
	signablePayload, err := query.SignablePayload()
	if err != nil {
		return err
	}
	return verifySignature(signablePayload, complianceData.Signature, otherVaspPubKeyResponse)
}

// verifySignature Verifies the signature of the uma request.
//
// Args:
//
//	payload: the payload that was signed.
//	signature: the hex-encoded signature.
//	otherVaspPubKeyResponse: the PubKeyResponse of the VASP who signed the payload.
func verifySignature(payload []byte, signature string, otherVaspPubKeyResponse protocol.PubKeyResponse) error {
	decodedSignature, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}
	parsedSignature, err := ecdsa.ParseDERSignature(decodedSignature)
	if err != nil {
		return err
	}
	pubKey, err := otherVaspPubKeyResponse.SigningPubKey()
	if err != nil {
		return err
	}
	secp256k1Key, err := secp256k1.ParsePubKey(pubKey)
	if err != nil {
		return err
	}
	sha256 := crypto.SHA256.New()
	_, err = sha256.Write(payload)
	if err != nil {
		return err
	}
	hashedPayload := sha256.Sum(nil)
	verified := parsedSignature.Verify(hashedPayload, secp256k1Key)

	if !verified {
		return errors.New("invalid uma signature")
	}

	return nil
}

// GetSignedLnurlpRequestUrl Creates a signed uma request URL. Should only be used for UMA requests.
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
	now := time.Now()
	unsignedRequest := protocol.LnurlpRequest{
		ReceiverAddress:       receiverAddress,
		IsSubjectToTravelRule: &isSubjectToTravelRule,
		VaspDomain:            &senderVaspDomain,
		Timestamp:             &now,
		Nonce:                 nonce,
		UmaVersion:            &umaVersion,
	}
	signablePayload, err := unsignedRequest.SignablePayload()
	if err != nil {
		return nil, err
	}
	signature, err := signPayload(signablePayload, signingPrivateKey)
	if err != nil {
		return nil, err
	}
	unsignedRequest.Signature = signature

	return unsignedRequest.EncodeToUrl()
}

// IsUmaLnurlpQuery Checks if the given URL is a valid UMA request. If this returns false,
// You should try to process the request as a regular LNURLp request to fall back to LNURL-PAY.
func IsUmaLnurlpQuery(url url.URL) bool {
	query, err := ParseLnurlpRequest(url)
	// If err is an UnsupportedVersionError, the request is still an UMA request, but the version is not supported.
	// The version negotiation should be handled by the VASP when parsing the request.
	var unsupportedVersionError UnsupportedVersionError
	if errors.As(err, &unsupportedVersionError) {
		return true
	}
	return err == nil && query != nil && query.IsUmaRequest()
}

// ParseLnurlpRequest Parse Parses the message into an LnurlpRequest object.
// Args:
//
//	url: the full URL of the uma request.
func ParseLnurlpRequest(url url.URL) (*protocol.LnurlpRequest, error) {
	return ParseLnurlpRequestWithReceiverDomain(url, url.Host)
}

// ParseLnurlpRequestWithReceiverDomain Parses the message into an LnurlpRequest object using an overridden receiver UMA domain.
//
// This is useful for cases where the receiver domain is not the same as the incoming request Host, for example when the
// request is being proxied to another internal service.
// Args:
//
//	url: the full URL of the uma request.
//	receiverDomain: the domain of the receiver UMA of the payment. This is used to override the domain in the URL.
func ParseLnurlpRequestWithReceiverDomain(url url.URL, receiverDomain string) (*protocol.LnurlpRequest, error) {
	query := url.Query()
	signature := query.Get("signature")
	vaspDomain := query.Get("vaspDomain")
	nonce := query.Get("nonce")
	isSubjectToTravelRule := strings.ToLower(query.Get("isSubjectToTravelRule")) == "true"
	umaVersion := query.Get("umaVersion")
	timestamp := query.Get("timestamp")
	var timestampAsTime *time.Time
	if timestamp != "" {
		timestampAsString, dateErr := strconv.ParseInt(timestamp, 10, 64)
		if dateErr != nil {
			return nil, errors.New("invalid timestamp")
		}
		timestampAsTimeVal := time.Unix(timestampAsString, 0)
		timestampAsTime = &timestampAsTimeVal
	}

	if umaVersion != "" && !IsVersionSupported(umaVersion) {
		return nil, UnsupportedVersionError{
			UnsupportedVersion:     umaVersion,
			SupportedMajorVersions: GetSupportedMajorVersions(),
		}
	}

	pathParts := strings.Split(url.Path, "/")
	if len(pathParts) != 4 || pathParts[1] != ".well-known" || pathParts[2] != "lnurlp" {
		return nil, errors.New("invalid uma request path")
	}
	receiverAddress := pathParts[3] + "@" + receiverDomain

	nilIfEmpty := func(s string) *string {
		if s == "" {
			return nil
		}
		return &s
	}

	return &protocol.LnurlpRequest{
		ReceiverAddress:       receiverAddress,
		VaspDomain:            nilIfEmpty(vaspDomain),
		UmaVersion:            nilIfEmpty(umaVersion),
		Signature:             nilIfEmpty(signature),
		Nonce:                 nilIfEmpty(nonce),
		Timestamp:             timestampAsTime,
		IsSubjectToTravelRule: &isSubjectToTravelRule,
	}, nil
}

// VerifyUmaLnurlpQuerySignature Verifies the signature on an uma Lnurlp query based on the public key of the VASP making the request.
//
// Args:
//
//	query: the signed query to verify.
//	otherVaspPubKeyResponse: the PubKeyResponse of the VASP making this request in bytes.
//	nonceCache: the NonceCache cache to use to prevent replay attacks.
func VerifyUmaLnurlpQuerySignature(query protocol.UmaLnurlpRequest, otherVaspPubKeyResponse protocol.PubKeyResponse, nonceCache NonceCache) error {
	err := nonceCache.CheckAndSaveNonce(query.Nonce, query.Timestamp)
	if err != nil {
		return err
	}
	signablePayload, err := query.SignablePayload()
	if err != nil {
		return err
	}
	return verifySignature(signablePayload, query.Signature, otherVaspPubKeyResponse)
}

func GetLnurlpResponse(
	request protocol.LnurlpRequest,
	callback string,
	encodedMetadata string,
	minSendableSats int64,
	maxSendableSats int64,
	privateKeyBytes *[]byte,
	requiresTravelRuleInfo *bool,
	payerDataOptions *protocol.CounterPartyDataOptions,
	currencyOptions *[]protocol.Currency,
	receiverKycStatus *protocol.KycStatus,
	commentCharsAllowed *int,
	nostrPubkey *string,
) (*protocol.LnurlpResponse, error) {
	isUmaRequest := request.IsUmaRequest()
	var complianceResponse *protocol.LnurlComplianceResponse
	var umaVersion *string

	if isUmaRequest {
		requiredUmaFields := map[string]interface{}{
			"privateKeyBytes":        privateKeyBytes,
			"requiresTravelRuleInfo": requiresTravelRuleInfo,
			"payerDataOptions":       payerDataOptions,
			"receiverKycStatus":      receiverKycStatus,
			"currencyOptions":        currencyOptions,
		}
		for fieldName, fieldValue := range requiredUmaFields {
			if fieldValue == nil {
				return nil, errors.New("missing required field for UMA: " + fieldName)
			}
		}
		var err error
		umaVersion, err = SelectLowerVersion(*request.UmaVersion, UmaProtocolVersion)
		if err != nil {
			return nil, err
		}

		complianceResponse, err = getSignedLnurlpComplianceResponse(request, *privateKeyBytes, *requiresTravelRuleInfo, *receiverKycStatus)
		if err != nil {
			return nil, err
		}

		// UMA always requires compliance and identifier fields:
		if payerDataOptions == nil {
			payerDataOptions = &protocol.CounterPartyDataOptions{}
		}
		(*payerDataOptions)[protocol.CounterPartyDataFieldCompliance.String()] = protocol.CounterPartyDataOption{Mandatory: true}
		(*payerDataOptions)[protocol.CounterPartyDataFieldIdentifier.String()] = protocol.CounterPartyDataOption{Mandatory: true}
	}

	// Ensure currencies are correctly serialized:
	if umaVersion != nil {
		umaVersionParsed, err := ParseVersion(*umaVersion)
		if err != nil && umaVersionParsed != nil && umaVersionParsed.Major == 0 {
			for i := range *currencyOptions {
				(*currencyOptions)[i].UmaMajorVersion = 0
			}
		}
	}

	var allowsNostr *bool = nil
	if nostrPubkey != nil {
		trueValue := true
		allowsNostr = &trueValue
	}
	return &protocol.LnurlpResponse{
		Tag:                 "protocol.PayRequest",
		Callback:            callback,
		MinSendable:         minSendableSats * 1000,
		MaxSendable:         maxSendableSats * 1000,
		EncodedMetadata:     encodedMetadata,
		Currencies:          currencyOptions,
		RequiredPayerData:   payerDataOptions,
		Compliance:          complianceResponse,
		UmaVersion:          umaVersion,
		CommentCharsAllowed: commentCharsAllowed,
		NostrPubkey:         nostrPubkey,
		AllowsNostr:         allowsNostr,
	}, nil
}

func getSignedLnurlpComplianceResponse(
	query protocol.LnurlpRequest,
	privateKeyBytes []byte,
	isSubjectToTravelRule bool,
	receiverKycStatus protocol.KycStatus,
) (*protocol.LnurlComplianceResponse, error) {
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
	return &protocol.LnurlComplianceResponse{
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
//	otherVaspPubKeyResponse: the PubKeyResponse of the VASP making this request in bytes.
//	nonceCache: the NonceCache cache to use to prevent replay attacks.
func VerifyUmaLnurlpResponseSignature(response protocol.UmaLnurlpResponse, otherVaspPubKeyResponse protocol.PubKeyResponse, nonceCache NonceCache) error {
	err := nonceCache.CheckAndSaveNonce(response.Compliance.Nonce, time.Unix(response.Compliance.Timestamp, 0))
	if err != nil {
		return err
	}
	return verifySignature(response.SignablePayload(), response.Compliance.Signature, otherVaspPubKeyResponse)
}

func ParseLnurlpResponse(bytes []byte) (*protocol.LnurlpResponse, error) {
	var response protocol.LnurlpResponse
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

// GetUmaPayRequest Creates a signed UMA pay request. For non-UMA LNURL requests, just construct a protocol.PayRequest directly.
//
// Args:
//
//			amount: the amount of the payment in the smallest unit of the specified currency (i.e. cents for USD).
//			receiverEncryptionPubKey: the public key of the receiver that will be used to encrypt the travel rule information.
//			sendingVaspPrivateKey: the private key of the VASP that is sending the payment. This will be used to sign the request.
//			receivingCurrencyCode: the code of the currency that the receiver will receive for this payment.
//			isAmountInReceivingCurrency: whether the amount field is specified in the smallest unit of the receiving
//				currency or in msats (if false).
//			payerIdentifier: the identifier of the sender. For example, $alice@vasp1.com
//			umaMajorVersion: the major version of UMA used for this request. If non-UMA, this version is still relevant
//	         for which LUD-21 spec to follow. For the older LUD-21 spec, this should be 0. For the newer LUD-21 spec,
//	         this should be 1.
//			payerName: the name of the sender (optional).
//			payerEmail: the email of the sender (optional).
//			trInfo: the travel rule information. This will be encrypted before sending to the receiver.
//			trInfoFormat: the standardized format of the travel rule information (e.g. IVMS). Null indicates raw json or a
//				custom format, or no travel rule information.
//			payerKycStatus: whether the sender is a KYC'd customer of the sending VASP.
//			payerUtxos: the list of UTXOs of the sender's channels that might be used to fund the payment.
//		 	payerNodePubKey: If known, the public key of the sender's node. If supported by the receiving VASP's compliance provider,
//		        this will be used to pre-screen the sender's UTXOs for compliance purposes.
//			utxoCallback: the URL that the receiver will call to send UTXOs of the channel that the receiver used to receive
//				the payment once it completes.
//			requestedPayeeData: the payer data options that the sender is requesting about the receiver.
//			comment: a comment that the sender would like to include with the payment. This can only be included
//		        if the receiver included the `commentAllowed` field in the lnurlp response. The length of
//		        the comment must be less than or equal to the value of `commentAllowed`.
func GetUmaPayRequest(
	amount int64,
	receiverEncryptionPubKey []byte,
	sendingVaspPrivateKey []byte,
	receivingCurrencyCode string,
	isAmountInReceivingCurrency bool,
	payerIdentifier string,
	umaMajorVersion int,
	payerName *string,
	payerEmail *string,
	trInfo *string,
	trInfoFormat *protocol.TravelRuleFormat,
	payerKycStatus protocol.KycStatus,
	payerUtxos *[]string,
	payerNodePubKey *string,
	utxoCallback string,
	requestedPayeeData *protocol.CounterPartyDataOptions,
	comment *string,
) (*protocol.PayRequest, error) {
	return GetUmaPayRequestWithInvoice(
		amount,
		receiverEncryptionPubKey,
		sendingVaspPrivateKey,
		receivingCurrencyCode,
		isAmountInReceivingCurrency,
		payerIdentifier,
		umaMajorVersion,
		payerName,
		payerEmail,
		trInfo,
		trInfoFormat,
		payerKycStatus,
		payerUtxos,
		payerNodePubKey,
		utxoCallback,
		requestedPayeeData,
		comment,
		nil,
	)
}

// GetUmaPayRequestWithInvoice Creates a signed UMA pay request to pay an UMA invoice. For non-UMA LNURL requests, just construct a protocol.PayRequest directly.
//
// Args:
//
//				amount: the amount of the payment in the smallest unit of the specified currency (i.e. cents for USD).
//				receiverEncryptionPubKey: the public key of the receiver that will be used to encrypt the travel rule information.
//				sendingVaspPrivateKey: the private key of the VASP that is sending the payment. This will be used to sign the request.
//				receivingCurrencyCode: the code of the currency that the receiver will receive for this payment.
//				isAmountInReceivingCurrency: whether the amount field is specified in the smallest unit of the receiving
//					currency or in msats (if false).
//				payerIdentifier: the identifier of the sender. For example, $alice@vasp1.com
//				umaMajorVersion: the major version of UMA used for this request. If non-UMA, this version is still relevant
//		         for which LUD-21 spec to follow. For the older LUD-21 spec, this should be 0. For the newer LUD-21 spec,
//		         this should be 1.
//				payerName: the name of the sender (optional).
//				payerEmail: the email of the sender (optional).
//				trInfo: the travel rule information. This will be encrypted before sending to the receiver.
//				trInfoFormat: the standardized format of the travel rule information (e.g. IVMS). Null indicates raw json or a
//					custom format, or no travel rule information.
//				payerKycStatus: whether the sender is a KYC'd customer of the sending VASP.
//				payerUtxos: the list of UTXOs of the sender's channels that might be used to fund the payment.
//			 	payerNodePubKey: If known, the public key of the sender's node. If supported by the receiving VASP's compliance provider,
//			        this will be used to pre-screen the sender's UTXOs for compliance purposes.
//				utxoCallback: the URL that the receiver will call to send UTXOs of the channel that the receiver used to receive
//					the payment once it completes.
//				requestedPayeeData: the payer data options that the sender is requesting about the receiver.
//				comment: a comment that the sender would like to include with the payment. This can only be included
//			        if the receiver included the `commentAllowed` field in the lnurlp response. The length of
//			        the comment must be less than or equal to the value of `commentAllowed`.
//	         invoiceUUID: the UUID of the invoice that the sender is paying.
func GetUmaPayRequestWithInvoice(
	amount int64,
	receiverEncryptionPubKey []byte,
	sendingVaspPrivateKey []byte,
	receivingCurrencyCode string,
	isAmountInReceivingCurrency bool,
	payerIdentifier string,
	umaMajorVersion int,
	payerName *string,
	payerEmail *string,
	trInfo *string,
	trInfoFormat *protocol.TravelRuleFormat,
	payerKycStatus protocol.KycStatus,
	payerUtxos *[]string,
	payerNodePubKey *string,
	utxoCallback string,
	requestedPayeeData *protocol.CounterPartyDataOptions,
	comment *string,
	invoiceUUID *string,
) (*protocol.PayRequest, error) {
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
	if requestedPayeeData == nil {
		requestedPayeeData = &protocol.CounterPartyDataOptions{}
	}
	// UMA always requires compliance and identifier fields:
	(*requestedPayeeData)[protocol.CounterPartyDataFieldCompliance.String()] = protocol.CounterPartyDataOption{Mandatory: true}
	(*requestedPayeeData)[protocol.CounterPartyDataFieldIdentifier.String()] = protocol.CounterPartyDataOption{Mandatory: true}

	sendingAmountCurrencyCode := &receivingCurrencyCode
	if !isAmountInReceivingCurrency {
		sendingAmountCurrencyCode = nil
	}

	complianceDataMap, err := complianceData.AsMap()
	if err != nil {
		return nil, err
	}

	return &protocol.PayRequest{
		SendingAmountCurrencyCode: sendingAmountCurrencyCode,
		ReceivingCurrencyCode:     &receivingCurrencyCode,
		Amount:                    amount,
		PayerData: &protocol.PayerData{
			protocol.CounterPartyDataFieldName.String():       payerName,
			protocol.CounterPartyDataFieldEmail.String():      payerEmail,
			protocol.CounterPartyDataFieldIdentifier.String(): payerIdentifier,
			protocol.CounterPartyDataFieldCompliance.String(): complianceDataMap,
		},
		RequestedPayeeData: requestedPayeeData,
		Comment:            comment,
		UmaMajorVersion:    umaMajorVersion,
		InvoiceUUID:        invoiceUUID,
	}, nil
}

func getSignedCompliancePayerData(
	receiverEncryptionPubKeyBytes []byte,
	sendingVaspPrivateKeyBytes []byte,
	payerIdentifier string,
	trInfo *string,
	trInfoFormat *protocol.TravelRuleFormat,
	payerKycStatus protocol.KycStatus,
	payerUtxos *[]string,
	payerNodePubKey *string,
	utxoCallback string,
) (*protocol.CompliancePayerData, error) {
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

	return &protocol.CompliancePayerData{
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
	pubKey, err := eciesgo.NewPublicKeyFromBytes(receiverEncryptionPubKey)
	if err != nil {
		return nil, err
	}

	encryptedTrInfoBytes, err := eciesgo.Encrypt(pubKey, []byte(trInfo))
	if err != nil {
		return nil, err
	}

	encryptedTrInfoHex := hex.EncodeToString(encryptedTrInfoBytes)
	return &encryptedTrInfoHex, nil
}

func ParsePayRequest(bytes []byte) (*protocol.PayRequest, error) {
	var response protocol.PayRequest
	err := json.Unmarshal(bytes, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

type InvoiceCreator interface {
	CreateInvoice(amountMsats int64, metadata string, receiverIdentifier *string) (*string, error)
}

func addInvoiceUUIDToMetadata(metadata string, invoiceUUID string) (string, error) {
	var data [][]interface{}
	err := json.Unmarshal([]byte(metadata), &data)
	if err != nil {
		return "", err
	}
	invoice := []interface{}{"text/uma-invoice", invoiceUUID}
	data = append(data, invoice)
	updatedJSON, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(updatedJSON), nil
}

// GetPayReqResponse Creates an uma pay request response with an encoded invoice.
//
// Args:
//
//		query: the uma pay request.
//		invoiceCreator: the object that will create the invoice.
//		metadata: the metadata that will be added to the invoice's metadata hash field. Note that this should not include
//		    the extra payer data. That will be appended automatically.
//		receivingCurrencyCode: the code of the currency that the receiver will receive for this payment.
//		receivingCurrencyDecimals: the number of decimal places in the specified currency. For example, USD has 2
//			decimal places. This should align with the decimals field returned for the chosen currency in the LNURLP
//			response.
//		conversionRate: milli-satoshis per the smallest unit of the specified currency. This rate is committed to by the
//	    	receiving VASP until the invoice expires.
//		receiverFeesMillisats: the fees charged (in millisats) by the receiving VASP to convert to the target currency.
//		    This is separate from the conversion rate.
//		receiverChannelUtxos: the list of UTXOs of the receiver's channels that might be used to fund the payment.
//		receiverNodePubKey: If known, the public key of the receiver's node. If supported by the sending VASP's compliance provider,
//	        this will be used to pre-screen the receiver's UTXOs for compliance purposes.
//		utxoCallback: the URL that the receiving VASP will call to send UTXOs of the channel that the receiver used to
//	    	receive the payment once it completes.
//		payeeData: the payee data which was requested by the sender. Can be nil if no payee data was requested or is
//			mandatory. The data provided does not need to include compliance data, as it will be added automatically.
//		receivingVaspPrivateKey: the private key of the VASP that is receiving the payment. This will be used to sign the request.
//		payeeIdentifier: the identifier of the receiver. For example, $bob@vasp2.com
//		disposable: This field may be used by a WALLET to decide whether the initial LNURL link will be stored locally
//			for later reuse or erased. If disposable is null, it should be interpreted as true, so if SERVICE intends
//			its LNURL links to be stored it must return `disposable: false`. UMA should never return
//			`disposable: false`. See LUD-11.
//		successAction: an optional action that the wallet should take once the payment is complete. See LUD-09.
func GetPayReqResponse(
	request protocol.PayRequest,
	invoiceCreator InvoiceCreator,
	metadata string,
	receivingCurrencyCode *string,
	receivingCurrencyDecimals *int,
	conversionRate *float64,
	receiverFeesMillisats *int64,
	receiverChannelUtxos *[]string,
	receiverNodePubKey *string,
	utxoCallback *string,
	payeeData *protocol.PayeeData,
	receivingVaspPrivateKey *[]byte,
	payeeIdentifier *string,
	disposable *bool,
	successAction *map[string]string,
) (*protocol.PayReqResponse, error) {
	if request.SendingAmountCurrencyCode != nil && *request.SendingAmountCurrencyCode != *receivingCurrencyCode {
		return nil, errors.New("the sdk only supports sending in either SAT or the receiving currency")
	}
	err := validatePayReqCurrencyFields(receivingCurrencyCode, receivingCurrencyDecimals, conversionRate, receiverFeesMillisats)
	if err != nil {
		return nil, err
	}
	conversionRateOrOne := 1.0
	if conversionRate != nil {
		conversionRateOrOne = *conversionRate
	}
	feesOrZero := int64(0)
	if receiverFeesMillisats != nil {
		feesOrZero = *receiverFeesMillisats
	}
	msatsAmount := request.Amount
	if receivingCurrencyCode != nil && request.SendingAmountCurrencyCode != nil {
		msatsAmount = int64(math.Round(float64(request.Amount)*(conversionRateOrOne))) + feesOrZero
	}

	payerDataStr := ""
	if request.PayerData != nil {
		encodedPayerData, err := json.Marshal(*(request.PayerData))
		if err != nil {
			return nil, err
		}
		payerDataStr = string(encodedPayerData)
	}
	if request.InvoiceUUID != nil {
		var err error
		metadata, err = addInvoiceUUIDToMetadata(metadata, *request.InvoiceUUID)
		if err != nil {
			return nil, err
		}
	}
	encodedInvoice, err := invoiceCreator.CreateInvoice(msatsAmount, metadata+payerDataStr, payeeIdentifier)
	if err != nil {
		return nil, err
	}
	var complianceData *protocol.CompliancePayeeData
	if request.IsUmaRequest() {
		err = validateUmaPayReqFields(
			receivingCurrencyCode,
			receivingCurrencyDecimals,
			conversionRate,
			receiverFeesMillisats,
			receiverChannelUtxos,
			receiverNodePubKey,
			payeeIdentifier,
			receivingVaspPrivateKey,
		)
		if err != nil {
			return nil, err
		}

		payerIdentifier := request.PayerData.Identifier()
		var utxos []string
		if receiverChannelUtxos != nil {
			utxos = *receiverChannelUtxos
		}
		complianceData, err = getSignedCompliancePayeeData(
			*receivingVaspPrivateKey,
			*payerIdentifier,
			*payeeIdentifier,
			utxos,
			receiverNodePubKey,
			utxoCallback,
		)
		if err != nil {
			return nil, err
		}
		if payeeData == nil {
			payeeData = &protocol.PayeeData{
				protocol.CounterPartyDataFieldIdentifier.String(): *payeeIdentifier,
			}
		} else if (*payeeData)[protocol.CounterPartyDataFieldIdentifier.String()] == nil {
			(*payeeData)[protocol.CounterPartyDataFieldIdentifier.String()] = *payeeIdentifier
		}
		if existingCompliance := (*payeeData)[protocol.CounterPartyDataFieldCompliance.String()]; existingCompliance == nil {
			complianceDataAsMap, err := complianceData.AsMap()
			if err != nil {
				return nil, err
			}
			(*payeeData)[protocol.CounterPartyDataFieldCompliance.String()] = complianceDataAsMap
		}
	}

	receivingCurrencyAmount := &request.Amount
	if request.SendingAmountCurrencyCode == nil {
		receivingCurrencyAmountVal := int64(math.Round(float64(msatsAmount-feesOrZero) / conversionRateOrOne))
		receivingCurrencyAmount = &receivingCurrencyAmountVal
	}
	if request.UmaMajorVersion == 0 {
		receivingCurrencyAmount = nil
	}
	var paymentInfo *protocol.PayReqResponsePaymentInfo
	if receivingCurrencyCode != nil {
		paymentInfo = &protocol.PayReqResponsePaymentInfo{
			Amount:                   receivingCurrencyAmount,
			CurrencyCode:             *receivingCurrencyCode,
			Multiplier:               *conversionRate,
			Decimals:                 *receivingCurrencyDecimals,
			ExchangeFeesMillisatoshi: *receiverFeesMillisats,
		}
	}
	return &protocol.PayReqResponse{
		EncodedInvoice:  *encodedInvoice,
		Routes:          []protocol.Route{},
		PaymentInfo:     paymentInfo,
		PayeeData:       payeeData,
		Disposable:      disposable,
		SuccessAction:   successAction,
		UmaMajorVersion: request.UmaMajorVersion,
	}, nil
}

func validatePayReqCurrencyFields(
	receivingCurrencyCode *string,
	receivingCurrencyDecimals *int,
	conversionRate *float64,
	receiverFeesMillisats *int64,
) error {
	numNilFields := 0
	if receivingCurrencyCode == nil {
		numNilFields++
	}
	if receivingCurrencyDecimals == nil {
		numNilFields++
	}
	if conversionRate == nil {
		numNilFields++
	}
	if receiverFeesMillisats == nil {
		numNilFields++
	}
	if numNilFields != 0 && numNilFields != 4 {
		return errors.New("invalid currency fields. must be all nil or all non-nil")
	}
	return nil
}

func validateUmaPayReqFields(
	receivingCurrencyCode *string,
	receivingCurrencyDecimals *int,
	conversionRate *float64,
	receiverFeesMillisats *int64,
	receiverChannelUtxos *[]string,
	receiverNodePubKey *string,
	payeeIdentifier *string,
	signingPrivateKeyBytes *[]byte,
) error {
	if receivingCurrencyCode == nil || receivingCurrencyDecimals == nil || conversionRate == nil || receiverFeesMillisats == nil {
		return errors.New("missing currency fields required for UMA")
	}

	if payeeIdentifier == nil {
		return errors.New("missing required UMA field payeeIdentifier")
	}

	if signingPrivateKeyBytes == nil {
		return errors.New("missing required UMA field signingPrivateKeyBytes")
	}

	if receiverChannelUtxos == nil && receiverNodePubKey == nil {
		return errors.New("missing required UMA fields. receiverChannelUtxos and/or receiverNodePubKey is required")
	}
	return nil
}

func getSignedCompliancePayeeData(
	receivingVaspPrivateKeyBytes []byte,
	payerIdentifier string,
	payeeIdentifier string,
	receiverChannelUtxos []string,
	receiverNodePubKey *string,
	utxoCallback *string,
) (*protocol.CompliancePayeeData, error) {
	timestamp := time.Now().Unix()
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	complianceData := protocol.CompliancePayeeData{
		Utxos:              receiverChannelUtxos,
		NodePubKey:         receiverNodePubKey,
		UtxoCallback:       utxoCallback,
		Signature:          nil,
		SignatureNonce:     nonce,
		SignatureTimestamp: &timestamp,
	}
	payloadString, err := complianceData.SignablePayload(payerIdentifier, payeeIdentifier)
	if err != nil {
		return nil, err
	}
	signature, err := signPayload([]byte(payloadString), receivingVaspPrivateKeyBytes)
	if err != nil {
		return nil, err
	}
	complianceData.Signature = signature
	return &complianceData, nil
}

// ParsePayReqResponse Parses the uma pay request response from a raw response body.
func ParsePayReqResponse(bytes []byte) (*protocol.PayReqResponse, error) {
	var response protocol.PayReqResponse
	err := response.UnmarshalJSON(bytes)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// VerifyPayReqResponseSignature Verifies the signature on an uma pay request response based on the public key of the
// VASP making the request.
//
// Args:
//
//	response: the signed response to verify.
//	otherVaspPubKeyResponse: the PubKeyResponse of the VASP making this request.
//	nonceCache: the NonceCache cache to use to prevent replay attacks.
//	payerIdentifier: the identifier of the sender. For example, $alice@vasp1.com
//	payeeIdentifier: the identifier of the receiver. For example, $bob@vasp2.com
func VerifyPayReqResponseSignature(
	response *protocol.PayReqResponse,
	otherVaspPubKeyResponse protocol.PubKeyResponse,
	nonceCache NonceCache,
	payerIdentifier string,
	payeeIdentifier string,
) error {
	complianceData, err := response.PayeeData.Compliance()
	if err != nil {
		return err
	}
	if complianceData == nil {
		return errors.New("missing compliance data")
	}
	if response.UmaMajorVersion == 0 {
		return errors.New("signatures were added to payreq responses in UMA v1. This response is from an UMA v0 receiving VASP")
	}
	err = nonceCache.CheckAndSaveNonce(
		*complianceData.SignatureNonce,
		time.Unix(*complianceData.SignatureTimestamp, 0),
	)
	if err != nil {
		return err
	}
	signablePayload, err := complianceData.SignablePayload(payerIdentifier, payeeIdentifier)
	if err != nil {
		return err
	}
	return verifySignature(signablePayload, *complianceData.Signature, otherVaspPubKeyResponse)
}

// GetPostTransactionCallback Creates a signed post transaction callback.
//
// Args:
//
//	utxos: UTXOs of the channels of the VASP initiating the callback.
//	vaspDomain: the domain of the VASP initiating the callback.
//	signingPrivateKey: the private key of the VASP initiating the callback. This will be used to sign the request.
func GetPostTransactionCallback(
	utxos []protocol.UtxoWithAmount,
	vaspDomain string,
	signingPrivateKey []byte,
) (*protocol.PostTransactionCallback, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().Unix()
	unsignedCallback := protocol.PostTransactionCallback{
		Utxos:      utxos,
		VaspDomain: &vaspDomain,
		Timestamp:  &timestamp,
		Nonce:      nonce,
	}
	signablePayload, err := unsignedCallback.SignablePayload()
	if err != nil {
		return nil, err
	}
	signature, err := signPayload(*signablePayload, signingPrivateKey)
	if err != nil {
		return nil, err
	}
	unsignedCallback.Signature = signature
	return &unsignedCallback, nil
}

func ParsePostTransactionCallback(bytes []byte) (*protocol.PostTransactionCallback, error) {
	var callback protocol.PostTransactionCallback
	err := json.Unmarshal(bytes, &callback)
	if err != nil {
		return nil, err
	}
	return &callback, nil
}

// VerifyPostTransactionCallbackSignature Verifies the signature on a post transaction callback based on the
// public key of the counterparty VASP.
//
// Args:
//
//	callback: the signed callback to verify.
//	otherVaspPubKeyResponse: the PubKeyResponse of the VASP making this request.
//	nonceCache: the NonceCache cache to use to prevent replay attacks.
func VerifyPostTransactionCallbackSignature(
	callback *protocol.PostTransactionCallback,
	otherVaspPubKeyResponse protocol.PubKeyResponse,
	nonceCache NonceCache,
) error {
	if callback.Signature == nil || callback.Nonce == nil || callback.Timestamp == nil {
		return errors.New("missing signature. Is this a UMA v0 callback? UMA v0 does not require signatures")
	}
	err := nonceCache.CheckAndSaveNonce(*callback.Nonce, time.Unix(*callback.Timestamp, 0))
	if err != nil {
		return err
	}
	signablePayload, err := callback.SignablePayload()
	if err != nil {
		return err
	}
	return verifySignature(*signablePayload, *callback.Signature, otherVaspPubKeyResponse)
}

func CreateUmaInvoice(
	receiverUma string,
	amount uint64,
	receivingCurrency protocol.InvoiceCurrency,
	expiration uint64,
	callback string,
	isSubjectToTravelRule bool,
	requiredPayerData *protocol.CounterPartyDataOptions,
	commentCharsAllowed *int,
	receiverKycStatus *protocol.KycStatus,
	invoiceLimit *uint64,
	senderUma *string,
	signingPrivateKey []byte,
) (*protocol.UmaInvoice, error) {
	uuid := uuid.New().String()
	invoice := protocol.UmaInvoice{
		ReceiverUma:           receiverUma,
		InvoiceUUID:           uuid,
		Amount:                amount,
		ReceivingCurrency:     receivingCurrency,
		Expiration:            expiration,
		IsSubjectToTravelRule: isSubjectToTravelRule,
		RequiredPayerData:     requiredPayerData,
		// TODO: modify the version once ready, all current version cannot support UMA invoice.
		// Since this only add fields and features to the protocol, this won't break the current
		// UMA version so it can be a minor version bump.
		UmaVersions:         UmaProtocolVersion,
		CommentCharsAllowed: commentCharsAllowed,
		SenderUma:           senderUma,
		MaxNumPayments:      invoiceLimit,
		KycStatus:           receiverKycStatus,
		Callback:            callback,
		Signature:           nil,
	}
	signablePayload, err := invoice.MarshalTLV()
	if err != nil {
		return nil, err
	}
	signature, err := signPayloadToBytes(signablePayload, signingPrivateKey)
	if err != nil {
		return nil, err
	}
	invoice.Signature = &signature
	return &invoice, nil
}

func DecodeUmaInvoice(invoice string) (*protocol.UmaInvoice, error) {
	return protocol.FromBech32String(invoice)
}

func VerifyUmaInvoiceSignature(invoice protocol.UmaInvoice, otherVaspPubKeyResponse protocol.PubKeyResponse) error {
	unsignedInvoice := invoice
	unsignedInvoice.Signature = nil
	signablePayload, err := unsignedInvoice.MarshalTLV()
	if err != nil {
		return err
	}
	signatureString := hex.EncodeToString(*invoice.Signature)
	return verifySignature(signablePayload, signatureString, otherVaspPubKeyResponse)
}

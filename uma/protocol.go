package uma

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// LnurlpRequest is the first request in the UMA protocol.
// It is sent by the VASP that is sending the payment to find out information about the receiver.
type LnurlpRequest struct {
	// ReceiverAddress is the address of the user at VASP2 that is receiving the payment.
	ReceiverAddress string
	// Nonce is a random string that is used to prevent replay attacks.
	Nonce string
	// Signature is the base64-encoded signature of sha256(ReceiverAddress|Nonce|Timestamp).
	Signature string
	// IsSubjectToTravelRule indicates VASP1 is a financial institution that requires travel rule information.
	IsSubjectToTravelRule bool
	// VaspDomain is the domain of the VASP that is sending the payment. It will be used by VASP2 to fetch the public keys of VASP1.
	VaspDomain string
	// Timestamp is the unix timestamp of when the request was sent. Used in the signature.
	Timestamp time.Time
	// UmaVersion is the version of the UMA protocol that VASP1 prefers to use for this transaction. For the version
	// negotiation flow, see https://static.swimlanes.io/87f5d188e080cb8e0494e46f80f2ae74.png
	UmaVersion string
}

func (q *LnurlpRequest) EncodeToUrl() (*url.URL, error) {
	receiverAddressParts := strings.Split(q.ReceiverAddress, "@")
	if len(receiverAddressParts) != 2 {
		return nil, errors.New("invalid receiver address")
	}
	scheme := "https"
	if IsDomainLocalhost(receiverAddressParts[1]) {
		scheme = "http"
	}
	lnurlpUrl := url.URL{
		Scheme: scheme,
		Host:   receiverAddressParts[1],
		Path:   fmt.Sprintf("/.well-known/lnurlp/%s", receiverAddressParts[0]),
	}
	queryParams := lnurlpUrl.Query()
	queryParams.Add("signature", q.Signature)
	queryParams.Add("vaspDomain", q.VaspDomain)
	queryParams.Add("nonce", q.Nonce)
	queryParams.Add("isSubjectToTravelRule", strconv.FormatBool(q.IsSubjectToTravelRule))
	queryParams.Add("timestamp", strconv.FormatInt(q.Timestamp.Unix(), 10))
	queryParams.Add("umaVersion", q.UmaVersion)
	lnurlpUrl.RawQuery = queryParams.Encode()
	return &lnurlpUrl, nil
}

func (q *LnurlpRequest) signablePayload() []byte {
	payloadString := strings.Join([]string{q.ReceiverAddress, q.Nonce, strconv.FormatInt(q.Timestamp.Unix(), 10)}, "|")
	return []byte(payloadString)
}

// LnurlpResponse is the response to the LnurlpRequest.
// It is sent by the VASP that is receiving the payment to provide information to the sender about the receiver.
type LnurlpResponse struct {
	Tag               string                  `json:"tag"`
	Callback          string                  `json:"callback"`
	MinSendable       int64                   `json:"minSendable"`
	MaxSendable       int64                   `json:"maxSendable"`
	EncodedMetadata   string                  `json:"metadata"`
	Currencies        []Currency              `json:"currencies"`
	RequiredPayerData CounterPartyDataOptions `json:"payerData"`
	Compliance        LnurlComplianceResponse `json:"compliance"`
	// UmaVersion is the version of the UMA protocol that VASP2 has chosen for this transaction based on its own support
	// and VASP1's specified preference in the LnurlpRequest. For the version negotiation flow, see
	// https://static.swimlanes.io/87f5d188e080cb8e0494e46f80f2ae74.png
	UmaVersion string `json:"umaVersion"`
}

// LnurlComplianceResponse is the `compliance` field  of the LnurlpResponse.
type LnurlComplianceResponse struct {
	// KycStatus indicates whether VASP2 has KYC information about the receiver.
	KycStatus KycStatus `json:"kycStatus"`
	// Signature is the base64-encoded signature of sha256(ReceiverAddress|Nonce|Timestamp).
	Signature string `json:"signature"`
	// Nonce is a random string that is used to prevent replay attacks.
	Nonce string `json:"signatureNonce"`
	// Timestamp is the unix timestamp of when the request was sent. Used in the signature.
	Timestamp int64 `json:"signatureTimestamp"`
	// IsSubjectToTravelRule indicates whether VASP2 is a financial institution that requires travel rule information.
	IsSubjectToTravelRule bool `json:"isSubjectToTravelRule"`
	// ReceiverIdentifier is the identifier of the receiver at VASP2.
	ReceiverIdentifier string `json:"receiverIdentifier"`
}

func (r *LnurlpResponse) signablePayload() []byte {
	payloadString := strings.Join([]string{
		r.Compliance.ReceiverIdentifier,
		r.Compliance.Nonce,
		strconv.FormatInt(r.Compliance.Timestamp, 10),
	}, "|")
	return []byte(payloadString)
}

// PayRequest is the request sent by the sender to the receiver to retrieve an invoice.
type PayRequest struct {
	// CurrencyCode is the ISO 3-digit currency code that the receiver will receive for this payment.
	CurrencyCode string `json:"currency"`
	// Amount is the amount that the receiver will receive for this payment in the smallest unit of the specified currency (i.e. cents for USD).
	Amount int64 `json:"amount"`
	// PayerData is the data that the sender will send to the receiver to identify themselves.
	PayerData PayerData `json:"payerData"`
	// RequestedPayeeData is the data that the sender is requesting about the payee.
	RequestedPayeeData *CounterPartyDataOptions `json:"payeeData"`
}

func (q *PayRequest) Encode() ([]byte, error) {
	return json.Marshal(q)
}

func (q *PayRequest) signablePayload() ([]byte, error) {
	senderAddress := q.PayerData.Identifier()
	if senderAddress == nil || *senderAddress == "" {
		return nil, errors.New("payer data is missing")
	}
	complianceData, err := q.PayerData.Compliance()
	if err != nil {
		return nil, err
	}
	if complianceData == nil {
		return nil, errors.New("compliance data is missing")
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

// PayReqResponse is the response sent by the receiver to the sender to provide an invoice.
type PayReqResponse struct {
	// EncodedInvoice is the BOLT11 invoice that the sender will pay.
	EncodedInvoice string `json:"pr"`
	// Routes is usually just an empty list from legacy LNURL, which was replaced by route hints in the BOLT11 invoice.
	Routes      []Route                   `json:"routes"`
	PaymentInfo PayReqResponsePaymentInfo `json:"paymentInfo"`
	PayeeData   *PayeeData                `json:"payeeData"`
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
	// CurrencyCode is the currency code that the receiver will receive for this payment.
	CurrencyCode string `json:"currencyCode"`
	// Multiplier is the conversion rate. It is the number of millisatoshis that the receiver will receive for 1 unit of the specified currency.
	// In this context, this is just for convenience. The conversion rate is also baked into the invoice amount itself.
	// `invoice amount = amount * multiplier + exchangeFeesMillisatoshi`
	Multiplier float64 `json:"multiplier"`
	// Decimals is the number of digits after the decimal point for the receiving currency. For example, in USD, by
	// convention, there are 2 digits for cents - $5.95. In this case, `Decimals` would be 2. This should align with the
	// currency's `Decimals` field in the LNURLP response. It is included here for convenience. See
	// [UMAD-04](/uma-04-local-currency.md) for details, edge cases, and examples.
	Decimals int `json:"decimals"`
	// ExchangeFeesMillisatoshi is the fees charged (in millisats) by the receiving VASP for this transaction. This is
	// separate from the Multiplier.
	ExchangeFeesMillisatoshi int64 `json:"exchangeFeesMillisatoshi"`
}

func (c *CompliancePayeeData) signablePayload(payerIdentifier string, payeeIdentifier string) ([]byte, error) {
	if c == nil {
		return nil, errors.New("compliance data is missing")
	}
	payloadString := strings.Join([]string{
		payerIdentifier,
		payeeIdentifier,
		c.SignatureNonce,
		strconv.FormatInt(c.SignatureTimestamp, 10),
	}, "|")
	return []byte(payloadString), nil
}

// PubKeyResponse is sent from a VASP to another VASP to provide its public keys.
// It is the response to GET requests at `/.well-known/lnurlpubkey`.
type PubKeyResponse struct {
	// SigningPubKeyHex is used to verify signatures from a VASP. Hex-encoded byte array.
	SigningPubKeyHex string `json:"signingPubKey"`
	// EncryptionPubKeyHex is used to encrypt TR info sent to a VASP. Hex-encoded byte array.
	EncryptionPubKeyHex string `json:"encryptionPubKey"`
	// ExpirationTimestamp [Optional] Seconds since epoch at which these pub keys must be refreshed.
	// They can be safely cached until this expiration (or forever if null).
	ExpirationTimestamp *int64 `json:"expirationTimestamp"`
}

func (r *PubKeyResponse) SigningPubKey() ([]byte, error) {
	return hex.DecodeString(r.SigningPubKeyHex)
}

func (r *PubKeyResponse) EncryptionPubKey() ([]byte, error) {
	return hex.DecodeString(r.EncryptionPubKeyHex)
}

// UtxoWithAmount is a pair of utxo and amount transferred over that corresponding channel.
// It can be used to register payment for KYT.
type UtxoWithAmount struct {
	// Utxo The utxo of the channel over which the payment went through in the format of <transaction_hash>:<output_index>.
	Utxo string `json:"utxo"`

	// Amount The amount of funds transferred in the payment in mSats.
	Amount int64 `json:"amountMsats"`
}

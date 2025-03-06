package protocol

import (
	"strconv"
	"strings"
)

// LnurlpResponse is the response to the LnurlpRequest.
// It is sent by the VASP that is receiving the payment to provide information to the sender about the receiver.
type LnurlpResponse struct {
	Tag             string `json:"tag"`
	Callback        string `json:"callback"`
	MinSendable     int64  `json:"minSendable"`
	MaxSendable     int64  `json:"maxSendable"`
	EncodedMetadata string `json:"metadata"`
	// Currencies is the list of currencies that the receiver can quote. See LUD-21. Required for UMA.
	Currencies *[]Currency `json:"currencies,omitempty"`
	// RequiredPayerData the data about the payer that the sending VASP must provide in order to send a payment.
	RequiredPayerData *CounterPartyDataOptions `json:"payerData,omitempty"`
	// Compliance is compliance-related data from the receiving VASP for UMA.
	Compliance *LnurlComplianceResponse `json:"compliance,omitempty"`
	// UmaVersion is the version of the UMA protocol that VASP2 has chosen for this transaction based on its own support
	// and VASP1's specified preference in the LnurlpRequest. For the version negotiation flow, see
	// https://static.swimlanes.io/87f5d188e080cb8e0494e46f80f2ae74.png
	UmaVersion *string `json:"umaVersion,omitempty"`
	// CommentCharsAllowed is the number of characters that the sender can include in the comment field of the pay request.
	CommentCharsAllowed *int `json:"commentAllowed,omitempty"`
	// NostrPubkey is an optional nostr pubkey used for nostr zaps (NIP-57). If set, it should be a valid BIP-340 public
	// key in hex format.
	NostrPubkey *string `json:"nostrPubkey,omitempty"`
	// AllowsNostr should be set to true if the receiving VASP allows nostr zaps (NIP-57).
	AllowsNostr *bool `json:"allowsNostr,omitempty"`
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

func (r *LnurlpResponse) IsUmaResponse() bool {
	return r.Compliance != nil && r.UmaVersion != nil && r.Currencies != nil && r.RequiredPayerData != nil
}

func (r *LnurlpResponse) AsUmaResponse() *UmaLnurlpResponse {
	if !r.IsUmaResponse() {
		return nil
	}
	return &UmaLnurlpResponse{
		LnurlpResponse:      *r,
		Currencies:          *r.Currencies,
		RequiredPayerData:   *r.RequiredPayerData,
		Compliance:          *r.Compliance,
		UmaVersion:          *r.UmaVersion,
		CommentCharsAllowed: r.CommentCharsAllowed,
		NostrPubkey:         r.NostrPubkey,
		AllowsNostr:         r.AllowsNostr,
	}
}

// UmaLnurlpResponse is the UMA response to the LnurlpRequest.
// It is sent by the VASP that is receiving the payment to provide information to the sender about the receiver.
type UmaLnurlpResponse struct {
	LnurlpResponse
	// Currencies is the list of currencies that the receiver can quote. See LUD-21. Required for UMA.
	Currencies []Currency `json:"currencies"`
	// RequiredPayerData the data about the payer that the sending VASP must provide in order to send a payment.
	RequiredPayerData CounterPartyDataOptions `json:"payerData"`
	// Compliance is compliance-related data from the receiving VASP for UMA.
	Compliance LnurlComplianceResponse `json:"compliance"`
	// UmaVersion is the version of the UMA protocol that VASP2 has chosen for this transaction based on its own support
	// and VASP1's specified preference in the LnurlpRequest. For the version negotiation flow, see
	// https://static.swimlanes.io/87f5d188e080cb8e0494e46f80f2ae74.png
	UmaVersion string `json:"umaVersion"`
	// CommentCharsAllowed is the number of characters that the sender can include in the comment field of the pay request.
	CommentCharsAllowed *int `json:"commentAllowed,omitempty"`
	// NostrPubkey is an optional nostr pubkey used for nostr zaps (NIP-57). If set, it should be a valid BIP-340 public
	// key in hex format.
	NostrPubkey *string `json:"nostrPubkey,omitempty"`
	// AllowsNostr should be set to true if the receiving VASP allows nostr zaps (NIP-57).
	AllowsNostr *bool `json:"allowsNostr,omitempty"`
}

func (r *UmaLnurlpResponse) SignablePayload() []byte {
	payloadString := strings.Join([]string{
		r.Compliance.ReceiverIdentifier,
		r.Compliance.Nonce,
		strconv.FormatInt(r.Compliance.Timestamp, 10),
	}, "|")
	return []byte(payloadString)
}

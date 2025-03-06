package protocol

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/uma-universal-money-address/uma-go-sdk/uma/errors"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/generated"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/utils"
)

// LnurlpRequest is the first request in the UMA protocol.
// It is sent by the VASP that is sending the payment to find out information about the receiver.
type LnurlpRequest struct {
	// ReceiverAddress is the address of the user at VASP2 that is receiving the payment.
	ReceiverAddress string
	// Nonce is a random string that is used to prevent replay attacks.
	Nonce *string
	// Signature is the base64-encoded signature of sha256(ReceiverAddress|Nonce|Timestamp).
	Signature *string
	// IsSubjectToTravelRule indicates VASP1 is a financial institution that requires travel rule information.
	IsSubjectToTravelRule *bool
	// VaspDomain is the domain of the VASP that is sending the payment. It will be used by VASP2 to fetch the public keys of VASP1.
	VaspDomain *string
	// Timestamp is the unix timestamp of when the request was sent. Used in the signature.
	Timestamp *time.Time
	// UmaVersion is the version of the UMA protocol that VASP1 prefers to use for this transaction. For the version
	// negotiation flow, see https://static.swimlanes.io/87f5d188e080cb8e0494e46f80f2ae74.png
	UmaVersion *string
}

// AsUmaRequest returns the request as an UmaLnurlpRequest if it is a valid UMA request, otherwise it returns nil.
// This is useful for validation and avoiding nil pointer dereferences.
func (q *LnurlpRequest) AsUmaRequest() *UmaLnurlpRequest {
	if !q.IsUmaRequest() {
		return nil
	}
	return &UmaLnurlpRequest{
		LnurlpRequest:         *q,
		ReceiverAddress:       q.ReceiverAddress,
		Nonce:                 *q.Nonce,
		Signature:             *q.Signature,
		IsSubjectToTravelRule: q.IsSubjectToTravelRule != nil && *q.IsSubjectToTravelRule,
		VaspDomain:            *q.VaspDomain,
		Timestamp:             *q.Timestamp,
		UmaVersion:            *q.UmaVersion,
	}
}

// IsUmaRequest returns true if the request is a valid UMA request, otherwise, if any fields are missing, it returns false.
func (q *LnurlpRequest) IsUmaRequest() bool {
	return q.VaspDomain != nil && q.Nonce != nil && q.Signature != nil && q.Timestamp != nil && q.UmaVersion != nil
}

func (q *LnurlpRequest) EncodeToUrl() (*url.URL, error) {
	receiverAddressParts := strings.Split(q.ReceiverAddress, "@")
	if len(receiverAddressParts) != 2 {
		return nil, &errors.UmaError{
			Reason:    "invalid receiver address",
			ErrorCode: generated.InvalidInput,
		}
	}
	scheme := "https"
	if utils.IsDomainLocalhost(receiverAddressParts[1]) {
		scheme = "http"
	}
	lnurlpUrl := url.URL{
		Scheme: scheme,
		Host:   receiverAddressParts[1],
		Path:   fmt.Sprintf("/.well-known/lnurlp/%s", receiverAddressParts[0]),
	}
	queryParams := lnurlpUrl.Query()
	if q.IsUmaRequest() {
		queryParams.Add("signature", *q.Signature)
		queryParams.Add("vaspDomain", *q.VaspDomain)
		queryParams.Add("nonce", *q.Nonce)
		isSubjectToTravelRule := *q.IsSubjectToTravelRule
		queryParams.Add("isSubjectToTravelRule", strconv.FormatBool(isSubjectToTravelRule))
		queryParams.Add("timestamp", strconv.FormatInt(q.Timestamp.Unix(), 10))
		queryParams.Add("umaVersion", *q.UmaVersion)
	}
	lnurlpUrl.RawQuery = queryParams.Encode()
	return &lnurlpUrl, nil
}

// UmaLnurlpRequest is the first request in the UMA protocol.
// It is sent by the VASP that is sending the payment to find out information about the receiver.
type UmaLnurlpRequest struct {
	LnurlpRequest
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

func (q *LnurlpRequest) SignablePayload() ([]byte, error) {
	if q.Timestamp == nil || q.Nonce == nil {
		return nil, &errors.UmaError{
			Reason:    "timestamp and nonce are required for signing",
			ErrorCode: generated.MissingRequiredUmaParameters,
		}
	}
	payloadString := strings.Join([]string{q.ReceiverAddress, *q.Nonce, strconv.FormatInt(q.Timestamp.Unix(), 10)}, "|")
	return []byte(payloadString), nil
}

package protocol

import (
	"encoding/hex"
	"encoding/json"

	"github.com/uma-universal-money-address/uma-go-sdk/uma/errors"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/generated"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/utils"
)

// PubKeyResponse is sent from a VASP to another VASP to provide its public keys.
// It is the response to GET requests at `/.well-known/lnurlpubkey`.
type PubKeyResponse struct {
	// SigningCertChain is the PEM-encoded certificate chain used to verify signatures from a VASP.
	SigningCertChain *string
	// EncryptionCertChain is the PEM-encoded certificate chain used to encrypt TR info sent to a VASP.
	EncryptionCertChain *string
	// SigningPubKeyHex is used to verify signatures from a VASP. Hex-encoded byte array.
	SigningPubKeyHex *string
	// EncryptionPubKeyHex is used to encrypt TR info sent to a VASP. Hex-encoded byte array.
	EncryptionPubKeyHex *string
	// ExpirationTimestamp [Optional] Seconds since epoch at which these pub keys must be refreshed.
	// They can be safely cached until this expiration (or forever if null).
	ExpirationTimestamp *int64
}

func (r *PubKeyResponse) SigningPubKey() ([]byte, error) {
	if r.SigningCertChain != nil {
		publicKey, err := utils.ExtractPubkeyFromPemCertificateChain(r.SigningCertChain)
		if err != nil {
			return nil, err
		}
		return publicKey.SerializeUncompressed(), nil
	} else if r.SigningPubKeyHex != nil {
		publicKey, err := hex.DecodeString(*r.SigningPubKeyHex)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	} else {
		return nil, &errors.UmaError{
			Reason:    "signingPubKeyHex is nil",
			ErrorCode: generated.InvalidPubkeyFormat,
		}
	}
}

func (r *PubKeyResponse) EncryptionPubKey() ([]byte, error) {
	if r.EncryptionCertChain != nil {
		publicKey, err := utils.ExtractPubkeyFromPemCertificateChain(r.EncryptionCertChain)
		if err != nil {
			return nil, err
		}
		return publicKey.SerializeUncompressed(), nil
	} else if r.EncryptionPubKeyHex != nil {
		publicKey, err := hex.DecodeString(*r.EncryptionPubKeyHex)
		if err != nil {
			return nil, err
		}
		return publicKey, nil
	} else {
		return nil, &errors.UmaError{
			Reason:    "encryptionPubKeyHex is nil",
			ErrorCode: generated.InvalidPubkeyFormat,
		}
	}
}

func (r *PubKeyResponse) MarshalJSON() ([]byte, error) {
	signingCertChainHexDer, err := utils.ConvertPemCertificateChainToHexEncodedDer(r.SigningCertChain)
	if err != nil {
		return nil, err
	}
	encryptionCertChainHexDer, err := utils.ConvertPemCertificateChainToHexEncodedDer(r.EncryptionCertChain)
	if err != nil {
		return nil, err
	}
	m := pubKeyResponseJson{
		&signingCertChainHexDer,
		&encryptionCertChainHexDer,
		r.SigningPubKeyHex,
		r.EncryptionPubKeyHex,
		r.ExpirationTimestamp,
	}
	return json.Marshal(m)
}

func (r *PubKeyResponse) UnmarshalJSON(data []byte) error {
	var temp pubKeyResponseJson
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	signingCertChainPem, err := utils.ConvertHexEncodedDerToPemCertChain(temp.SigningCertChainHexDer)
	if err != nil {
		return err
	}
	encryptionCertChainPem, err := utils.ConvertHexEncodedDerToPemCertChain(temp.EncryptionCertChainHexDer)
	if err != nil {
		return err
	}
	r.SigningCertChain = signingCertChainPem
	r.EncryptionCertChain = encryptionCertChainPem
	r.SigningPubKeyHex = temp.SigningPubKeyHex
	r.EncryptionPubKeyHex = temp.EncryptionPubKeyHex
	r.ExpirationTimestamp = temp.ExpirationTimestamp
	return nil
}

type pubKeyResponseJson struct {
	SigningCertChainHexDer    *[]string `json:"signingCertChain,omitempty"`
	EncryptionCertChainHexDer *[]string `json:"encryptionCertChain,omitempty"`
	SigningPubKeyHex          *string   `json:"signingPubKey,omitempty"`
	EncryptionPubKeyHex       *string   `json:"encryptionPubKey,omitempty"`
	ExpirationTimestamp       *int64    `json:"expirationTimestamp,omitempty"`
}

package protocol

import (
	"encoding/hex"
	"encoding/json"
	"errors"
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
		return hex.DecodeString(*r.SigningPubKeyHex)
	} else {
		return nil, errors.New("signingPubKeyHex is nil")
	}
}

func (r *PubKeyResponse) EncryptionPubKey() ([]byte, error) {
	if r.EncryptionCertChain != nil {
		publicKey, err := utils.ExtractPubkeyFromPemCertificateChain(r.EncryptionCertChain)
		if err != nil {
			return nil, err
		}
		return publicKey.SerializeUncompressed(), nil
	} else if r.EncryptionPubKeyHex == nil {
		return hex.DecodeString(*r.EncryptionPubKeyHex)
	} else {
		return nil, errors.New("encryptionPubKeyHex is nil")
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
	m := map[string]interface{}{
		"signingCertChain":    signingCertChainHexDer,
		"encryptionCertChain": encryptionCertChainHexDer,
		"signingPubKey":       r.SigningPubKeyHex,
		"encryptionPubKey":    r.EncryptionPubKeyHex,
		"expirationTimestamp": r.ExpirationTimestamp,
	}
	return json.Marshal(m)
}

func (r *PubKeyResponse) UnmarshalJSON(data []byte) error {
	var temp struct {
		SigningCertChainHexDer    *[]string `json:"signingCertChain"`
		EncryptionCertChainHexDer *[]string `json:"encryptionCertChain"`
		SigningPubKeyHex          string    `json:"signingPubKey"`
		EncryptionPubKeyHex       string    `json:"encryptionPubKey"`
		ExpirationTimestamp       *int64    `json:"expirationTimestamp"`
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	r.SigningCertChain, _ = utils.ConvertHexEncodedDerToPemCertChain(temp.SigningCertChainHexDer)
	r.EncryptionCertChain, _ = utils.ConvertHexEncodedDerToPemCertChain(temp.EncryptionCertChainHexDer)
	r.SigningPubKeyHex = &temp.SigningPubKeyHex
	r.EncryptionPubKeyHex = &temp.EncryptionPubKeyHex
	r.ExpirationTimestamp = temp.ExpirationTimestamp

	return nil
}

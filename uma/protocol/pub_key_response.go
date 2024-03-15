package protocol

import "encoding/hex"

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

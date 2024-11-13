package utils

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func SignPayloadToBytes(payload []byte, privateKeyBytes []byte) ([]byte, error) {
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

func SignPayload(payload []byte, privateKeyBytes []byte) (*string, error) {
	signature, err := SignPayloadToBytes(payload, privateKeyBytes)
	if err != nil {
		return nil, err
	}
	signatureString := hex.EncodeToString(signature)
	return &signatureString, nil
}

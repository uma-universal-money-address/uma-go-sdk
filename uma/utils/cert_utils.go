package utils

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
	"time"
)

func ExtractPubkeyFromPemCertificateChain(certChain string) (*secp256k1.PublicKey, error) {
	block, _ := pem.Decode([]byte(certChain))
	if block == nil {
		return nil, errors.New("failed to parse certificate chain PEM")
	}
	asn1Data := block.Bytes

	var v []*certificate
	for len(asn1Data) > 0 {
		cert := new(certificate)
		var err error
		asn1Data, err = asn1.Unmarshal(asn1Data, cert)
		if err != nil {
			return nil, err
		}
		v = append(v, cert)
	}

	if len(v) == 0 {
		return nil, errors.New("empty certificate chain")
	}

	return parseToSecp256k1PublicKey(&v[0].TBSCertificate.PublicKey)
}

func parseToSecp256k1PublicKey(keyData *publicKeyInfo) (*secp256k1.PublicKey, error) {
	asn1Data := keyData.PublicKey.RightAlign()
	return secp256k1.ParsePubKey(asn1Data)
}

type certificate struct {
	Raw                asn1.RawContent
	TBSCertificate     tbsCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Raw                asn1.RawContent
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          publicKeyInfo
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type validity struct {
	NotBefore, NotAfter time.Time
}

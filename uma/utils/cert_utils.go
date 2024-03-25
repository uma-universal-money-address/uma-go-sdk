package utils

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
	"time"
)

func ConvertPemCertificateChainToHexEncodedDer(certChain *string) ([]string, error) {
	if certChain == nil {
		return []string{}, nil
	}
	asn1Certs, err := getAsn1DataFromPemChain(certChain)
	if err != nil {
		return nil, err
	}
	var v []string
	for _, block := range *asn1Certs {
		v = append(v, hex.EncodeToString(block))
	}
	return v, nil
}

func ConvertHexEncodedDerToPemCertChain(hexDerCerts *[]string) (*string, error) {
	if hexDerCerts == nil || len(*hexDerCerts) == 0 {
		return nil, nil
	}
	var pemCertChain string
	for _, hexDerCert := range *hexDerCerts {
		derCert, err := hex.DecodeString(hexDerCert)
		if err != nil {
			return nil, err
		}
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derCert,
		}
		pemCertChain = pemCertChain + string(pem.EncodeToMemory(block))
	}
	return &pemCertChain, nil
}

func ExtractPubkeyFromPemCertificateChain(certChain *string) (*secp256k1.PublicKey, error) {
	asn1Certs, err := getAsn1DataFromPemChain(certChain)
	if err != nil {
		return nil, err
	}
	if len(*asn1Certs) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	cert := new(certificate)
	_, err = asn1.Unmarshal((*asn1Certs)[0], cert)
	if err != nil {
		return nil, err
	}
	return parseToSecp256k1PublicKey(&cert.TBSCertificate.PublicKey)
}

func getAsn1DataFromPemChain(certChain *string) (*[][]byte, error) {
	pemData := []byte(*certChain)
	var v [][]byte
	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		v = append(v, block.Bytes)
	}
	return &v, nil
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

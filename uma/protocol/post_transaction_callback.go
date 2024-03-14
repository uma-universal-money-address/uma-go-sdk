package protocol

import (
	"strconv"
	"strings"
)

// PostTransactionCallback is sent between VASPs after the payment is complete.
type PostTransactionCallback struct {
	// Utxos is a list of utxo/amounts corresponding to the VASPs channels.
	Utxos []UtxoWithAmount `json:"utxos"`
	// VaspDomain is the domain of the VASP that is sending the callback.
	// It will be used by the VASP to fetch the public keys of its counterparty.
	VaspDomain string `json:"vaspDomain"`
	// Signature is the base64-encoded signature of sha256(Nonce|Timestamp).
	Signature string `json:"signature"`
	// Nonce is a random string that is used to prevent replay attacks.
	Nonce string `json:"signatureNonce"`
	// Timestamp is the unix timestamp of when the request was sent. Used in the signature.
	Timestamp int64 `json:"signatureTimestamp"`
}

// UtxoWithAmount is a pair of utxo and amount transferred over that corresponding channel.
// It can be used to register payment for KYT.
type UtxoWithAmount struct {
	// Utxo The utxo of the channel over which the payment went through in the format of <transaction_hash>:<output_index>.
	Utxo string `json:"utxo"`

	// Amount The amount of funds transferred in the payment in mSats.
	Amount int64 `json:"amountMsats"`
}

func (c *PostTransactionCallback) SignablePayload() []byte {
	payloadString := strings.Join([]string{
		c.Nonce,
		strconv.FormatInt(c.Timestamp, 10),
	}, "|")
	return []byte(payloadString)
}

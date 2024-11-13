package protocol

// BackingSignature is a signature by a backing VASP that can attest to the authenticity of the message,
// along with its associated domain.
type BackingSignature struct {
	// Domain is the domain of the VASP that produced the signature. Public keys for this VASP will be fetched from
	// the domain at /.well-known/lnurlpubkey and used to verify the signature.
	Domain string `json:"domain"`

	// Signature is the signature of the payload.
	Signature string `json:"signature"`
}

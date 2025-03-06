// Generated error codes - DO NOT MODIFY MANUALLY

package generated

// ErrorCode represents an error code with an associated HTTP status code
type ErrorCode struct {
	Code           string
	HTTPStatusCode int
}

// Error code constants
var (
	// Error fetching counterparty public key for validating signatures or encrypting messages
	CounterpartyPubkeyFetchError = ErrorCode{Code: "COUNTERPARTY_PUBKEY_FETCH_ERROR", HTTPStatusCode: 424}

	// Error parsing the counterparty public key response
	InvalidPubkeyFormat = ErrorCode{Code: "INVALID_PUBKEY_FORMAT", HTTPStatusCode: 400}

	// The provided certificate chain is invalid
	CertChainInvalid = ErrorCode{Code: "CERT_CHAIN_INVALID", HTTPStatusCode: 400}

	// The provided certificate chain has expired
	CertChainExpired = ErrorCode{Code: "CERT_CHAIN_EXPIRED", HTTPStatusCode: 400}

	// The provided signature is not valid
	InvalidSignature = ErrorCode{Code: "INVALID_SIGNATURE", HTTPStatusCode: 401}

	// The provided timestamp is not valid
	InvalidTimestamp = ErrorCode{Code: "INVALID_TIMESTAMP", HTTPStatusCode: 400}

	// The provided nonce is not valid
	InvalidNonce = ErrorCode{Code: "INVALID_NONCE", HTTPStatusCode: 400}

	// An unexpected error occurred on the server
	InternalError = ErrorCode{Code: "INTERNAL_ERROR", HTTPStatusCode: 500}

	// This party does not support non-UMA LNURLs
	NonUmaLnurlNotSupported = ErrorCode{Code: "NON_UMA_LNURL_NOT_SUPPORTED", HTTPStatusCode: 403}

	// Missing required UMA parameters
	MissingRequiredUmaParameters = ErrorCode{Code: "MISSING_REQUIRED_UMA_PARAMETERS", HTTPStatusCode: 400}

	// The counterparty UMA version is not supported
	UnsupportedUmaVersion = ErrorCode{Code: "UNSUPPORTED_UMA_VERSION", HTTPStatusCode: 412}

	// Error parsing the LNURLP request
	ParseLnurlpRequestError = ErrorCode{Code: "PARSE_LNURLP_REQUEST_ERROR", HTTPStatusCode: 400}

	// This user has exceeded the velocity limit and is unable to receive payments at this time
	VelocityLimitExceeded = ErrorCode{Code: "VELOCITY_LIMIT_EXCEEDED", HTTPStatusCode: 403}

	// The user for this UMA was not found
	UserNotFound = ErrorCode{Code: "USER_NOT_FOUND", HTTPStatusCode: 404}

	// The user for this UMA is not ready to receive payments at this time
	UserNotReady = ErrorCode{Code: "USER_NOT_READY", HTTPStatusCode: 403}

	// The request corresponding to this callback URL was not found
	RequestNotFound = ErrorCode{Code: "REQUEST_NOT_FOUND", HTTPStatusCode: 404}

	// Error parsing the payreq request
	ParsePayreqRequestError = ErrorCode{Code: "PARSE_PAYREQ_REQUEST_ERROR", HTTPStatusCode: 400}

	// The amount provided is not within the min/max range
	AmountOutOfRange = ErrorCode{Code: "AMOUNT_OUT_OF_RANGE", HTTPStatusCode: 400}

	// The currency provided is not valid or supported
	InvalidCurrency = ErrorCode{Code: "INVALID_CURRENCY", HTTPStatusCode: 400}

	// Payments from this sender are not accepted
	SenderNotAccepted = ErrorCode{Code: "SENDER_NOT_ACCEPTED", HTTPStatusCode: 400}

	// Payer data is missing fields that are required by the receiver
	MissingMandatoryPayerData = ErrorCode{Code: "MISSING_MANDATORY_PAYER_DATA", HTTPStatusCode: 400}

	// Receiver does not recognize the mandatory payee data key
	UnrecognizedMandatoryPayeeDataKey = ErrorCode{Code: "UNRECOGNIZED_MANDATORY_PAYEE_DATA_KEY", HTTPStatusCode: 501}

	// Error parsing the utxo callback
	ParseUtxoCallbackError = ErrorCode{Code: "PARSE_UTXO_CALLBACK_ERROR", HTTPStatusCode: 400}

	// This party does not accept payments with the counterparty
	CounterpartyNotAllowed = ErrorCode{Code: "COUNTERPARTY_NOT_ALLOWED", HTTPStatusCode: 403}

	// Error parsing the LNURLP response
	ParseLnurlpResponseError = ErrorCode{Code: "PARSE_LNURLP_RESPONSE_ERROR", HTTPStatusCode: 400}

	// Error parsing the payreq response
	ParsePayreqResponseError = ErrorCode{Code: "PARSE_PAYREQ_RESPONSE_ERROR", HTTPStatusCode: 400}

	// The LNURLP request failed
	LnurlpRequestFailed = ErrorCode{Code: "LNURLP_REQUEST_FAILED", HTTPStatusCode: 424}

	// The payreq request failed
	PayreqRequestFailed = ErrorCode{Code: "PAYREQ_REQUEST_FAILED", HTTPStatusCode: 424}

	// No compatible UMA protocol version found between sender and receiver
	NoCompatibleUmaVersion = ErrorCode{Code: "NO_COMPATIBLE_UMA_VERSION", HTTPStatusCode: 424}

	// The provided invoice is invalid
	InvalidInvoice = ErrorCode{Code: "INVALID_INVOICE", HTTPStatusCode: 400}

	// The invoice has expired
	InvoiceExpired = ErrorCode{Code: "INVOICE_EXPIRED", HTTPStatusCode: 400}

	// The quote has expired
	QuoteExpired = ErrorCode{Code: "QUOTE_EXPIRED", HTTPStatusCode: 400}

	// The provided input is invalid
	InvalidInput = ErrorCode{Code: "INVALID_INPUT", HTTPStatusCode: 400}

	// The request format is invalid
	InvalidRequestFormat = ErrorCode{Code: "INVALID_REQUEST_FORMAT", HTTPStatusCode: 400}

	// This action is not permitted for this user
	Forbidden = ErrorCode{Code: "FORBIDDEN", HTTPStatusCode: 403}

	// This functionality is not implemented
	NotImplemented = ErrorCode{Code: "NOT_IMPLEMENTED", HTTPStatusCode: 501}

	// The requested quote was not found
	QuoteNotFound = ErrorCode{Code: "QUOTE_NOT_FOUND", HTTPStatusCode: 404}
)

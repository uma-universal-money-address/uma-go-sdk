package protocol

// PayReqResponse is the response sent by the receiver to the sender to provide an invoice.
type PayReqResponse struct {
	// EncodedInvoice is the BOLT11 invoice that the sender will pay.
	EncodedInvoice string `json:"pr"`
	// Routes is usually just an empty list from legacy LNURL, which was replaced by route hints in the BOLT11 invoice.
	Routes []Route `json:"routes"`
	// PaymentInfo is information about the payment that the receiver will receive. Includes Final currency-related
	// information for the payment. Required for UMA.
	PaymentInfo *PayReqResponsePaymentInfo `json:"paymentInfo"`
	// PayeeData The data about the receiver that the sending VASP requested in the payreq request.
	// Required for UMA.
	PayeeData *PayeeData `json:"payeeData"`
	// Disposable This field may be used by a WALLET to decide whether the initial LNURL link will  be stored locally
	// for later reuse or erased. If disposable is null, it should be interpreted as true, so if SERVICE intends its
	// LNURL links to be stored it must return `disposable: false`. UMA should never return `disposable: false` due to
	// signature nonce checks, etc. See LUD-11.
	Disposable *bool `json:"disposable"`
	// SuccessAction defines a struct which can be stored and shown to the user on payment success. See LUD-09.
	SuccessAction *map[string]string `json:"successAction"`
}

func (p *PayReqResponse) IsUmaResponse() bool {
	if p.PaymentInfo == nil || p.PayeeData == nil {
		return false
	}
	compliance, err := p.PayeeData.Compliance()
	if err != nil {
		return false
	}
	return compliance != nil
}

type Route struct {
	Pubkey string `json:"pubkey"`
	Path   []struct {
		Pubkey   string `json:"pubkey"`
		Fee      int64  `json:"fee"`
		Msatoshi int64  `json:"msatoshi"`
		Channel  string `json:"channel"`
	} `json:"path"`
}

type PayReqResponsePaymentInfo struct {
	// Amount is the amount that the receiver will receive in the receiving currency not including fees. The amount is
	//    specified in the smallest unit of the currency (eg. cents for USD).
	Amount int64 `json:"amount"`
	// CurrencyCode is the currency code that the receiver will receive for this payment.
	CurrencyCode string `json:"currencyCode"`
	// Multiplier is the conversion rate. It is the number of millisatoshis that the receiver will receive for 1 unit of
	//    the specified currency. In this context, this is just for convenience. The conversion rate is also baked into
	//    the invoice amount itself.
	//    `invoice amount = Amount * Multiplier + ExchangeFeesMillisatoshi`
	Multiplier float64 `json:"multiplier"`
	// Decimals is the number of digits after the decimal point for the receiving currency. For example, in USD, by
	// convention, there are 2 digits for cents - $5.95. In this case, `Decimals` would be 2. This should align with the
	// currency's `Decimals` field in the LNURLP response. It is included here for convenience. See
	// [UMAD-04](/uma-04-local-currency.md) for details, edge cases, and examples.
	Decimals int `json:"decimals"`
	// ExchangeFeesMillisatoshi is the fees charged (in millisats) by the receiving VASP for this transaction. This is
	// separate from the Multiplier.
	ExchangeFeesMillisatoshi int64 `json:"fee"`
}

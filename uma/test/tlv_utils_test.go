package uma_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/utils"
)

type BinaryCodableStruct struct {
	Data []byte
}

func (b *BinaryCodableStruct) MarshalBytes() ([]byte, error) {
	return b.Data, nil
}

func (b *BinaryCodableStruct) UnmarshalBytes(data []byte) error {
	b.Data = data
	return nil
}

type TLVUtilsTests struct {
	StringField              string  `tlv:"0"`
	IntField                 int     `tlv:"1"`
	BoolField                bool    `tlv:"2"`
	UInt64Field              uint64  `tlv:"3"`
	OptionalStringField      *string `tlv:"6"`
	OptionalEmptyStringField *string `tlv:"7"`
}

type TLVUtilsTestsMissingField struct {
	StringField string `tlv:"0"`
	IntField    int    `tlv:"1"`
	BoolField   bool   `tlv:"2"`
}

func (d *TLVUtilsTests) MarshalTLV() ([]byte, error) {
	return utils.MarshalTLV(d)
}

func (d *TLVUtilsTests) UnmarshalTLV(data []byte) error {
	return utils.UnmarshalTLV(d, data)
}

func TestSimpleTLVCoder(t *testing.T) {
	str := "optional"
	tlvUtilsTests := TLVUtilsTests{
		StringField:              "hello",
		IntField:                 42,
		BoolField:                true,
		UInt64Field:              123,
		OptionalStringField:      &str,
		OptionalEmptyStringField: nil,
	}

	data, err := tlvUtilsTests.MarshalTLV()
	if err != nil {
		t.Fatal(err)
	}

	var tlvUtilsTests2 TLVUtilsTests
	err = tlvUtilsTests2.UnmarshalTLV(data)
	if err != nil {
		t.Fatal(err)
	}

	if tlvUtilsTests.StringField != tlvUtilsTests2.StringField {
		t.Fatalf("expected %s, got %s", tlvUtilsTests.StringField, tlvUtilsTests2.StringField)
	}

	if tlvUtilsTests.IntField != tlvUtilsTests2.IntField {
		t.Fatalf("expected %d, got %d", tlvUtilsTests.IntField, tlvUtilsTests2.IntField)
	}

	if tlvUtilsTests.BoolField != tlvUtilsTests2.BoolField {
		t.Fatalf("expected %t, got %t", tlvUtilsTests.BoolField, tlvUtilsTests2.BoolField)
	}

	if tlvUtilsTests.UInt64Field != tlvUtilsTests2.UInt64Field {
		t.Fatalf("expected %d, got %d", tlvUtilsTests.UInt64Field, tlvUtilsTests2.UInt64Field)
	}

	if *tlvUtilsTests.OptionalStringField != *tlvUtilsTests2.OptionalStringField {
		t.Fatalf("expected %s, got %s", *tlvUtilsTests.OptionalStringField, *tlvUtilsTests2.OptionalStringField)
	}

	if tlvUtilsTests2.OptionalEmptyStringField != nil {
		t.Fatalf("expected optional empty string field to be nil")
	}
}

type NestedTLVUtilsTests struct {
	StringField        string              `tlv:"0"`
	IntField           int                 `tlv:"1"`
	BoolField          bool                `tlv:"2"`
	UInt64Field        uint64              `tlv:"3"`
	NestedField        TLVUtilsTests       `tlv:"4"`
	BinaryCodableField BinaryCodableStruct `tlv:"5"`
}

func TestNestedTLVCoder(t *testing.T) {
	nestedTLVUtilsTests := NestedTLVUtilsTests{
		StringField: "hello",
		IntField:    42,
		BoolField:   true,
		UInt64Field: 123,
		NestedField: TLVUtilsTests{
			StringField: "world",
			IntField:    43,
			BoolField:   false,
			UInt64Field: 124,
		},
		BinaryCodableField: BinaryCodableStruct{
			Data: []byte("binary"),
		},
	}

	data, err := utils.MarshalTLV(&nestedTLVUtilsTests)
	if err != nil {
		t.Fatal(err)
	}

	var nestedTLVUtilsTests2 NestedTLVUtilsTests
	err = utils.UnmarshalTLV(&nestedTLVUtilsTests2, data)
	if err != nil {
		t.Fatal(err)
	}

	if nestedTLVUtilsTests.StringField != nestedTLVUtilsTests2.StringField {
		t.Fatalf("expected %s, got %s", nestedTLVUtilsTests.StringField, nestedTLVUtilsTests2.StringField)
	}

	if nestedTLVUtilsTests.IntField != nestedTLVUtilsTests2.IntField {
		t.Fatalf("expected %d, got %d", nestedTLVUtilsTests.IntField, nestedTLVUtilsTests2.IntField)
	}

	if nestedTLVUtilsTests.BoolField != nestedTLVUtilsTests2.BoolField {
		t.Fatalf("expected %t, got %t", nestedTLVUtilsTests.BoolField, nestedTLVUtilsTests2.BoolField)
	}

	if nestedTLVUtilsTests.UInt64Field != nestedTLVUtilsTests2.UInt64Field {
		t.Fatalf("expected %d, got %d", nestedTLVUtilsTests.UInt64Field, nestedTLVUtilsTests2.UInt64Field)
	}

	if nestedTLVUtilsTests.NestedField.StringField != nestedTLVUtilsTests2.NestedField.StringField {
		t.Fatalf("expected %s, got %s", nestedTLVUtilsTests.NestedField.StringField, nestedTLVUtilsTests2.NestedField.StringField)
	}

	if nestedTLVUtilsTests.NestedField.IntField != nestedTLVUtilsTests2.NestedField.IntField {
		t.Fatalf("expected %d, got %d", nestedTLVUtilsTests.NestedField.IntField, nestedTLVUtilsTests2.NestedField.IntField)
	}

	if nestedTLVUtilsTests.NestedField.BoolField != nestedTLVUtilsTests2.NestedField.BoolField {
		t.Fatalf("expected %t, got %t", nestedTLVUtilsTests.NestedField.BoolField, nestedTLVUtilsTests2.NestedField.BoolField)
	}

	if nestedTLVUtilsTests.NestedField.UInt64Field != nestedTLVUtilsTests2.NestedField.UInt64Field {
		t.Fatalf("expected %d, got %d", nestedTLVUtilsTests.NestedField.UInt64Field, nestedTLVUtilsTests2.NestedField.UInt64Field)
	}

	if nestedTLVUtilsTests2.BinaryCodableField.Data == nil {
		t.Fatalf("expected binary codable field to be unmarshaled")
	}

	if string(nestedTLVUtilsTests2.BinaryCodableField.Data) != "binary" {
		t.Fatalf("expected binary codable field to be 'binary', got %s", nestedTLVUtilsTests2.BinaryCodableField.Data)
	}

}

func TestMissingFieldTLVCoder(t *testing.T) {
	tlvUtilsTests := TLVUtilsTestsMissingField{
		StringField: "hello",
		IntField:    42,
		BoolField:   true,
	}

	data, err := utils.MarshalTLV(&tlvUtilsTests)
	if err != nil {
		t.Fatal(err)
	}

	var tlvUtilsTests2 TLVUtilsTests
	err = utils.UnmarshalTLV(&tlvUtilsTests2, data)
	require.Error(t, err)
}

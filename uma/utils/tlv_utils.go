package utils

import (
	"fmt"
	"reflect"
	"strconv"
)

// BytesCodable is an interface for types that can be marshaled to and unmarshaled from bytes.
type BytesCodable interface {
	MarshalBytes() ([]byte, error)
	UnmarshalBytes([]byte) error
}

// TLVCodable is an interface for types that can be marshaled to and unmarshaled from TLV.
type TLVCodable interface {
	MarshalTLV() ([]byte, error)
	UnmarshalTLV([]byte) error
}

// MarshalTLV marshals a struct to TLV.
// It will marshals all the field with tag "tlv".
// The tagged value will be the type of
func MarshalTLV(v interface{}) ([]byte, error) {
	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("marshal requires a pointer to a struct")
	}

	val = reflect.Indirect(val)
	typ := val.Type()

	var handle func(field reflect.Value) ([]byte, error)
	handle = func(field reflect.Value) ([]byte, error) {
		switch field.Kind() {
		case reflect.String:
			return []byte(field.String()), nil
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return []byte(strconv.FormatInt(field.Int(), 10)), nil
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return []byte(strconv.FormatUint(field.Uint(), 10)), nil
		case reflect.Bool:
			if field.Bool() {
				return []byte{1}, nil
			} else {
				return []byte{0}, nil
			}
		case reflect.Ptr:
			if field.IsNil() {
				return nil, nil
			}
			return handle(reflect.Indirect(field))
		case reflect.Slice:
			return field.Bytes(), nil
		default:
			pointer := field.Addr().Interface()
			if coder, ok := pointer.(TLVCodable); ok {
				return coder.MarshalTLV()
			} else if coder, ok := pointer.(BytesCodable); ok {
				return coder.MarshalBytes()
			} else {
				return nil, fmt.Errorf("unsupported type %s", field.Kind())
			}
		}
	}

	var result []byte
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		tag := typ.Field(i).Tag.Get("tlv")
		if tag == "" {
			continue
		}
		tlv, err := strconv.Atoi(tag)
		if err != nil {
			return nil, err
		}

		content, err := handle(field)
		if err != nil {
			return nil, err
		}
		if content == nil {
			continue
		}
		result = append(result, byte(tlv))
		result = append(result, byte(len(content)))
		result = append(result, content...)
	}
	return result, nil
}

// UnmarshalTLV unmarshals a struct from TLV.
// It will unmarshals all the field with tag "tlv".
func UnmarshalTLV(v interface{}, data []byte) error {
	result := make(map[byte][]byte)
	for i := 0; i < len(data); {
		if i+2 > len(data) {
			return fmt.Errorf("incomplete TLV at position %d", i)
		}

		t := data[i]
		l := data[i+1]

		if i+2+int(l) > len(data) {
			return fmt.Errorf("incomplete value for type %d at position %d", t, i)
		}

		v := data[i+2 : i+2+int(l)]
		result[t] = v

		i += 2 + int(l)
	}

	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("unmarshal requires a pointer to a struct")
	}
	val = reflect.Indirect(val)
	var handle func(field reflect.Value, value []byte) error
	handle = func(field reflect.Value, value []byte) error {
		switch field.Kind() {
		case reflect.String:
			field.SetString(string(value))
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			i, err := strconv.ParseInt(string(value), 10, 64)
			if err != nil {
				return err
			}
			field.SetInt(i)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			i, err := strconv.ParseUint(string(value), 10, 64)
			if err != nil {
				return err
			}
			field.SetUint(i)
		case reflect.Bool:
			field.SetBool(value[0] != 0)
		case reflect.Ptr:
			if field.IsNil() {
				newValue := reflect.New(field.Type().Elem())
				field.Set(newValue)
			}
			return handle(field.Elem(), value)
		case reflect.Slice:
			field.SetBytes(value)
		default:
			pointer := field.Addr().Interface()
			if coder, ok := pointer.(TLVCodable); ok {
				err := coder.UnmarshalTLV(value)
				if err != nil {
					return err
				}
			} else if coder, ok := pointer.(BytesCodable); ok {
				err := coder.UnmarshalBytes(value)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("unsupported type %s", field.Kind())
			}
		}
		return nil
	}

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		tag := val.Type().Field(i).Tag.Get("tlv")
		if tag == "" {
			continue
		}
		tlv, err := strconv.Atoi(tag)
		if err != nil {
			return err
		}

		content, ok := result[byte(tlv)]
		if !ok {
			continue
		}

		err = handle(field, content)

		if err != nil {
			return err
		}
	}

	return nil
}

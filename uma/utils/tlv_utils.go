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
// The "tlv" tag value will be the type of the field.
func MarshalTLV(v interface{}) ([]byte, error) {
	val := reflect.ValueOf(v)
    if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("marshal requires a pointer to a struct")
    }

	val = reflect.Indirect(val)
    typ := val.Type()

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

		var content []byte

		switch field.Kind() {
		case reflect.String:
			content = []byte(field.String())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			content = []byte(strconv.FormatInt(field.Int(), 10))
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			content = []byte(strconv.FormatUint(field.Uint(), 10))
		case reflect.Struct:
			pointer := field.Addr().Interface()
			if coder, ok := pointer.(TLVCodable); ok {
				content, err = coder.MarshalTLV()
				if err != nil {
					return nil, err
				}
			} else if coder, ok := pointer.(BytesCodable); ok {
				content, err = coder.MarshalBytes()
				if err != nil {
					return nil, err
				}
			} else {
				return nil, fmt.Errorf("unsupported struct type %s", field.Type().Name())
			}
		case reflect.Bool:
			if field.Bool() {
				content = []byte{1}
			} else {
				content = []byte{0}
			}
		default:
			return nil, fmt.Errorf("unsupported type %s", field.Kind())
		}

		result = append(result, byte(tlv))
		result = append(result, byte(len(content)))
		result = append(result, content...)
	}
	return result, nil
}

// UnmarshalTLV unmarshals a struct from TLV.
// It will unmarshals all the field with tag "tlv".
// The "tlv" tag value will be the type of the field.
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

		switch field.Kind() {
		case reflect.String:
			field.SetString(string(content))
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			i, err := strconv.ParseInt(string(content), 10, 64)
			if err != nil {
				return err
			}
			field.SetInt(i)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			i, err := strconv.ParseUint(string(content), 10, 64)
			if err != nil {
				return err
			}
			field.SetUint(i)
		case reflect.Struct:
			pointer := field.Addr().Interface()
			if coder, ok := pointer.(TLVCodable); ok {
				err := coder.UnmarshalTLV(content)
				if err != nil {
					return err
				}
			} else if coder, ok := pointer.(BytesCodable); ok {
				err := coder.UnmarshalBytes(content)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("unsupported struct type %s", field.Type().Name())
			}
		case reflect.Bool:
			field.SetBool(content[0] != 0)
		default:
			return fmt.Errorf("unsupported type %s", field.Kind())
		}
	}

	return nil
}

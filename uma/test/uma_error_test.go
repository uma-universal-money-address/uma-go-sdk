package uma_test

import (
	"encoding/json"
	stderrors "errors"
	"testing"

	"github.com/uma-universal-money-address/uma-go-sdk/uma"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/errors"
	"github.com/uma-universal-money-address/uma-go-sdk/uma/generated"
)

func TestUnsupportedVersionError(t *testing.T) {
	unsupportedVersionError := uma.UnsupportedVersionError{
		UnsupportedVersion:     "1.2",
		SupportedMajorVersions: []int{0, 1},
	}

	errorJSON, _ := unsupportedVersionError.ToJSON()
	var errorMap map[string]interface{}
	err := json.Unmarshal([]byte(errorJSON), &errorMap)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if errorMap["status"] != "ERROR" {
		t.Errorf("Expected status ERROR, got %v", errorMap["status"])
	}
	if errorMap["reason"] != "unsupported version: 1.2" {
		t.Errorf("Expected reason 'unsupported version: 1.2', got %v", errorMap["reason"])
	}
	if errorMap["code"] != "UNSUPPORTED_UMA_VERSION" {
		t.Errorf("Expected code UNSUPPORTED_UMA_VERSION, got %v", errorMap["code"])
	}
	if errorMap["unsupportedVersion"] != "1.2" {
		t.Errorf("Expected unsupportedVersion '1.2', got %v", errorMap["unsupportedVersion"])
	}
	supportedVersions, ok := errorMap["supportedMajorVersions"].([]interface{})
	if !ok {
		t.Errorf("Expected supportedMajorVersions to be an array, got %T", errorMap["supportedMajorVersions"])
	} else {
		if len(supportedVersions) != 2 || supportedVersions[0] != float64(0) || supportedVersions[1] != float64(1) {
			t.Errorf("Expected supportedMajorVersions [0,1], got %v", supportedVersions)
		}
	}
	if unsupportedVersionError.ToHttpStatusCode() != 412 {
		t.Errorf("Expected HTTP status code 412, got %v", unsupportedVersionError.ToHttpStatusCode())
	}
}

func TestErrorToJSONResponseWithUmaError(t *testing.T) {
	umaErr := &errors.UmaError{
		Reason:    "test reason",
		ErrorCode: generated.InternalError,
	}

	jsonStr, statusCode, ok := errors.ErrorToJSONResponse(umaErr)

	if !ok {
		t.Error("Expected ok to be true for UmaError")
	}

	if statusCode != 500 {
		t.Errorf("Expected status code 500, got %d", statusCode)
	}

	var errorMap map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &errorMap)
	if err != nil {
		t.Errorf("Failed to unmarshal JSON: %v", err)
	}

	if errorMap["status"] != "ERROR" {
		t.Errorf("Expected status ERROR, got %v", errorMap["status"])
	}
	if errorMap["reason"] != "test reason" {
		t.Errorf("Expected reason 'test reason', got %v", errorMap["reason"])
	}
	if errorMap["code"] != "INTERNAL_ERROR" {
		t.Errorf("Expected code INTERNAL_ERROR, got %v", errorMap["code"])
	}
}

func TestErrorToJSONResponseWithStandardError(t *testing.T) {
	standardError := stderrors.New("standard error")

	_, _, ok := errors.ErrorToJSONResponse(standardError)

	if ok {
		t.Error("Expected ok to be false for standard error")
	}
}

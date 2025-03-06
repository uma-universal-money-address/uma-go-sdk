package errors

import (
	"encoding/json"

	"github.com/uma-universal-money-address/uma-go-sdk/uma/generated"
)

// UmaErrorInterface defines methods all UMA errors must implement
type UmaErrorInterface interface {
	error
	ToJSON() (string, error)
	ToHttpStatusCode() int
}

type UmaError struct {
	Reason    string
	ErrorCode generated.ErrorCode
}

func (e *UmaError) Error() string {
	return e.Reason
}

func (e *UmaError) ToJSON() (string, error) {
	data := map[string]interface{}{
		"status": "ERROR",
		"reason": e.Reason,
		"code":   e.ErrorCode.Code,
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func (e *UmaError) ToHttpStatusCode() int {
	return e.ErrorCode.HTTPStatusCode
}

func ErrorToJSONResponse(err error) (string, int, bool) {
	if umaErr, ok := err.(UmaErrorInterface); ok {
		json, _ := umaErr.ToJSON()
		return json, umaErr.ToHttpStatusCode(), true
	}
	return "", 0, false
}

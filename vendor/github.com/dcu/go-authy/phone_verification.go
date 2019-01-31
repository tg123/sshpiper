package authy

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// PhoneVerificationStart encapsulates the response from the Authy API when requesting a phone verification.
type PhoneVerificationStart struct {
	HTTPResponse *http.Response
	UUID         string `json:"uuid"`
	Message      string `json:"message"`
	Success      bool   `json:"success"`
	Carrier      string `json:"carrier"`
}

// NewPhoneVerificationStart receives a http request, parses the body and return an instance of PhoneVerification
func NewPhoneVerificationStart(response *http.Response) (*PhoneVerificationStart, error) {
	phoneVerification := &PhoneVerificationStart{HTTPResponse: response}
	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return phoneVerification, err
	}

	err = json.Unmarshal(body, &phoneVerification)
	if err != nil {
		return phoneVerification, err
	}

	return phoneVerification, nil
}

// PhoneVerificationCheck encapsulates the response from the Authy API when checking a phone verification.
type PhoneVerificationCheck struct {
	HTTPResponse *http.Response
	Message      string `json:"message"`
	Success      bool   `json:"success"`
}

// NewPhoneVerificationCheck receives a http request, parses the body and return an instance of PhoneVerification
func NewPhoneVerificationCheck(response *http.Response) (*PhoneVerificationCheck, error) {
	phoneVerification := &PhoneVerificationCheck{HTTPResponse: response}
	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return phoneVerification, err
	}

	err = json.Unmarshal(body, &phoneVerification)
	if err != nil {
		return phoneVerification, err
	}

	return phoneVerification, nil
}

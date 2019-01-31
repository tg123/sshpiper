package authy

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// PhoneCallRequest encapsulates the response from the Authy API
type PhoneCallRequest struct {
	HTTPResponse *http.Response
	Message      string `json:"message"`
}

// NewPhoneCallRequest returns an instance of a PhoneCallRequest
func NewPhoneCallRequest(response *http.Response) (*PhoneCallRequest, error) {
	request := &PhoneCallRequest{HTTPResponse: response}
	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		Logger.Println("Error reading from API:", err)
		return request, err
	}

	err = json.Unmarshal(body, &request)
	if err != nil {
		Logger.Println("Error parsing JSON:", err)
		return request, err
	}

	return request, nil
}

// Valid returns true if the request was valid.
func (request *PhoneCallRequest) Valid() bool {
	return request.HTTPResponse.StatusCode == 200
}

package authy

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

// SMSRequest encapsulates the response from the Authy API when requesting a SMS
type SMSRequest struct {
	HTTPResponse *http.Response
	Message      string `json:"message"`
}

// NewSMSRequest returns an instance of SMSRequest
func NewSMSRequest(response *http.Response) (*SMSRequest, error) {
	request := &SMSRequest{HTTPResponse: response}
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

// Valid returns true if the SMS was sent
func (request *SMSRequest) Valid() bool {
	return request.HTTPResponse.StatusCode == 200
}

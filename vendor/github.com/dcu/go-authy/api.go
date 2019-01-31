package authy

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gojektech/heimdall"
	"github.com/gojektech/heimdall/httpclient"
)

var (
	// Logger is the default logger of this package. You can override it with your own.
	Logger = log.New(os.Stderr, "[authy] ", log.LstdFlags)

	_Dialer = &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// DefaultTransport is the default transport struct for the HTTP client
	DefaultTransport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           _Dialer.DialContext,
		MaxIdleConns:          128,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 3 * time.Second,
	}
)

const (
	longPollingDelay = 2000 * time.Millisecond
)

const (
	// SMS indicates the message will be delivered via SMS
	SMS = "sms"

	// Voice indicates the message will be delivered via phone call
	Voice = "call"
)

// Details for OneTouch transaction
type Details map[string]string

// Authy contains credentials to connect to the Authy's API
type Authy struct {
	APIKey  string
	BaseURL string
	Client  heimdall.Client
}

// NewAuthyAPI returns an instance of Authy pointing to production.
func NewAuthyAPI(apiKey string) *Authy {
	apiURL := "https://api.authy.com"

	initalTimeout := 2 * time.Millisecond
	maxTimeout := 1000 * time.Millisecond
	exponentFactor := 2.0
	maximumJitterInterval := 2 * time.Millisecond
	backoff := heimdall.NewExponentialBackoff(initalTimeout, maxTimeout, exponentFactor, maximumJitterInterval)

	client := httpclient.NewClient(
		httpclient.WithHTTPTimeout(1*time.Second),
		httpclient.WithRetrier(heimdall.NewRetrier(backoff)),
		httpclient.WithRetryCount(4),
		httpclient.WithHTTPClient(&http.Client{
			Transport: DefaultTransport,
		}),
	)

	return &Authy{
		APIKey:  apiKey,
		BaseURL: apiURL,
		Client:  client,
	}
}

// RegisterUser register a new user given an email and phone number.
func (authy *Authy) RegisterUser(email string, countryCode int, phoneNumber string, params url.Values) (*User, error) {
	Logger.Println("Creating Authy user with", email, ",", phoneNumber, "and", countryCode)

	path := "/protected/json/users/new"

	params.Set("user[cellphone]", phoneNumber)
	params.Set("user[country_code]", strconv.Itoa(countryCode))
	params.Set("user[email]", email)

	response, err := authy.DoRequest("POST", path, params)

	if err != nil {
		return nil, err
	}

	userResponse, err := NewUser(response)
	return userResponse, err
}

// UserStatus returns a set of data about a user.
func (authy *Authy) UserStatus(id string, params url.Values) (*UserStatus, error) {
	Logger.Println("Finding Authy user with id", id)

	path := fmt.Sprintf("/protected/json/users/%s/status", id)

	response, err := authy.DoRequest("GET", path, params)
	if err != nil {
		return nil, err
	}

	statusResponse, err := NewUserStatus(response)
	return statusResponse, err
}

// VerifyToken verifies the given token
func (authy *Authy) VerifyToken(userID string, token string, params url.Values) (*TokenVerification, error) {
	path := "/protected/json/verify/" + url.QueryEscape(token) + "/" + url.QueryEscape(userID)

	response, err := authy.DoRequest("GET", path, params)

	if err != nil {
		Logger.Println("Error while contacting the API:", err)
		return nil, err
	}

	defer closeResponseBody(response)

	tokenVerification, err := NewTokenVerification(response)
	return tokenVerification, err
}

// RequestSMS requests a SMS for the given userID
func (authy *Authy) RequestSMS(userID string, params url.Values) (*SMSRequest, error) {
	path := "/protected/json/sms/" + url.QueryEscape(userID)
	response, err := authy.DoRequest("GET", path, params)
	if err != nil {
		return nil, err
	}

	defer closeResponseBody(response)
	smsVerification, err := NewSMSRequest(response)
	return smsVerification, err
}

// RequestPhoneCall requests a phone call for the given user
func (authy *Authy) RequestPhoneCall(userID string, params url.Values) (*PhoneCallRequest, error) {
	path := "/protected/json/call/" + url.QueryEscape(userID)

	response, err := authy.DoRequest("GET", path, params)
	if err != nil {
		return nil, err
	}

	defer closeResponseBody(response)
	smsVerification, err := NewPhoneCallRequest(response)
	return smsVerification, err
}

// SendApprovalRequest sends a OneTouch's approval request to the given user.
func (authy *Authy) SendApprovalRequest(userID string, message string, details Details, params url.Values) (*ApprovalRequest, error) {
	addParamsForOneTouch(params, message, details)
	path := fmt.Sprintf(`/onetouch/json/users/%s/approval_requests`, url.QueryEscape(userID))

	response, err := authy.DoRequest("POST", path, params)
	if err != nil {
		return nil, err
	}

	defer closeResponseBody(response)
	return NewApprovalRequest(response)
}

// FindApprovalRequest finds an approval request given its uuid.
func (authy *Authy) FindApprovalRequest(uuid string, params url.Values) (*ApprovalRequest, error) {
	path := fmt.Sprintf("/onetouch/json/approval_requests/%s", uuid)
	response, err := authy.DoRequest("GET", path, params)
	if err != nil {
		return nil, err
	}

	defer closeResponseBody(response)
	approvalRequest, err := NewApprovalRequest(response)
	if err != nil {
		return nil, err
	}

	approvalRequest.UUID = uuid
	return approvalRequest, nil
}

// WaitForApprovalRequest waits until the status of an approval request has changed or times out.
func (authy *Authy) WaitForApprovalRequest(uuid string, maxDuration time.Duration, params url.Values) (OneTouchStatus, error) {
	for maxDuration > 0 {
		request, err := authy.FindApprovalRequest(uuid, url.Values{})
		if err != nil {
			return OneTouchStatusPending, err
		}

		if request.Status != OneTouchStatusPending {
			return request.Status, nil
		}

		maxDuration -= longPollingDelay
		time.Sleep(longPollingDelay)
	}

	return OneTouchStatusExpired, nil
}

// StartPhoneVerification starts the phone verification process.
func (authy *Authy) StartPhoneVerification(countryCode int, phoneNumber string, via string, params url.Values) (*PhoneVerificationStart, error) {
	params.Set("country_code", strconv.Itoa(countryCode))
	params.Set("phone_number", phoneNumber)
	params.Set("via", via)

	path := fmt.Sprintf("/protected/json/phones/verification/start")
	response, err := authy.DoRequest("POST", path, params)
	if err != nil {
		return nil, err
	}

	defer closeResponseBody(response)
	return NewPhoneVerificationStart(response)
}

// CheckPhoneVerification checks the given verification code.
func (authy *Authy) CheckPhoneVerification(countryCode int, phoneNumber string, verificationCode string, params url.Values) (*PhoneVerificationCheck, error) {
	params.Set("country_code", strconv.Itoa(countryCode))
	params.Set("phone_number", phoneNumber)
	params.Set("verification_code", verificationCode)

	path := fmt.Sprintf("/protected/json/phones/verification/check")
	response, err := authy.DoRequest("GET", path, params)
	if err != nil {
		return nil, err
	}

	defer closeResponseBody(response)
	return NewPhoneVerificationCheck(response)
}

// DoRequest performs a HTTP request to the Authy API
func (authy *Authy) DoRequest(method string, path string, params url.Values) (*http.Response, error) {
	apiURL := authy.buildURL(path)

	// Set api_key to all requests.
	params.Set("api_key", authy.APIKey)

	var bodyReader io.Reader
	switch method {
	case "POST":
		{
			encodedParams := params.Encode()
			bodyReader = strings.NewReader(encodedParams)
		}
	case "GET":
		{
			apiURL += "?" + params.Encode()
		}
	}

	request, err := http.NewRequest(method, apiURL, bodyReader)
	if method == "POST" {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if err != nil {
		Logger.Println("Error creating HTTP request:", err)
		return nil, err
	}
	response, err := authy.Client.Do(request)

	return response, err
}

func (authy *Authy) buildURL(path string) string {
	if path[0] != '/' {
		path = "/" + path
	}
	url := authy.BaseURL + path

	return url
}

func closeResponseBody(response *http.Response) {
	err := response.Body.Close()
	if err != nil {
		Logger.Println("Error closing response body:", err)
	}
}

func addParamsForOneTouch(params url.Values, message string, details map[string]string) url.Values {
	params.Set("message", message)
	for key, value := range details {
		params.Set(fmt.Sprintf("details[%s]", key), value)
	}

	return params
}

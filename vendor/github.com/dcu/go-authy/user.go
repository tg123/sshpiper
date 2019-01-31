package authy

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
)

// User is an Authy User
type User struct {
	HTTPResponse *http.Response
	ID           string
	UserData     struct {
		ID int `json:"id"`
	} `json:"user"`
	Errors  map[string]string `json:"errors"`
	Message string            `json:"message"`
}

// UserStatus is a user with information loaded from Authy API
type UserStatus struct {
	HTTPResponse *http.Response
	ID           string
	StatusData   struct {
		ID          int      `json:"authy_id"`
		Confirmed   bool     `json:"confirmed"`
		Registered  bool     `json:"registered"`
		Country     int      `json:"country_code"`
		PhoneNumber string   `json:"phone_number"`
		Devices     []string `json:"devices"`
	} `json:"status"`
	Message string `json:"message"`
	Success bool   `json:"success"`
}

// NewUser returns an instance of User
func NewUser(httpResponse *http.Response) (*User, error) {
	userResponse := &User{HTTPResponse: httpResponse}

	defer closeResponseBody(httpResponse)
	body, err := ioutil.ReadAll(httpResponse.Body)

	if err != nil {
		Logger.Println("Error reading from API:", err)
		return userResponse, err
	}

	err = json.Unmarshal(body, userResponse)
	if err != nil {
		Logger.Println("Error parsing JSON:", err)
		return userResponse, err
	}

	userResponse.ID = strconv.Itoa(userResponse.UserData.ID)
	return userResponse, nil
}

// NewUserStatus returns an instance of UserStatus
func NewUserStatus(httpResponse *http.Response) (*UserStatus, error) {
	statusResponse := &UserStatus{HTTPResponse: httpResponse}

	defer closeResponseBody(httpResponse)

	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		Logger.Println("Error reading from API:", err)
		return statusResponse, err
	}

	err = json.Unmarshal(body, statusResponse)
	if err != nil {
		Logger.Println("Error parsing JSON:", err)
		return statusResponse, err
	}

	statusResponse.ID = strconv.Itoa(statusResponse.StatusData.ID)
	return statusResponse, nil
}

// Valid returns true if the user was created successfully
func (response *User) Valid() bool {
	return response.HTTPResponse.StatusCode == 200
}

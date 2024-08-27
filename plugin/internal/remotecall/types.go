package remotecall

type userKeyAuth struct {
	Key []byte `json:"key"`
}

type PrincipalType string

const PrincipalTypeUser PrincipalType = "user"

type UserKeyAuthResponse struct {
	PrincipalType PrincipalType `json:"principalType"`
	PrincipalID   string        `json:"principalID"`
}

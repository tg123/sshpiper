package azdevicecode

import (
	"context"

	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	a "github.com/microsoft/kiota-authentication-azure-go"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
)

type authClient struct {
	Config struct {
		TenantID string `long:"challenger-azdevicecode-tenantid" description:"Azure AD tenant id" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_TENANTID" ini-name:"challenger-azdevicecode-tenantid"`
		ClientID string `long:"challenger-azdevicecode-clientid" description:"Azure AD client id" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_CLIENTID" ini-name:"challenger-azdevicecode-clientid"`
		// Env         string `long:"challenger-azdevicecode-env" default:"AzurePublicCloud" description:"Azure AD Cloud to request" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_ENV" ini-name:"challenger-azdevicecode-env"`
		Scope       string `long:"challenger-azdevicecode-scope" default:"User.Read" description:"Permission scope when querying user info" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_SCOPE" ini-name:"challenger-azdevicecode-scope"`
		NoReadGraph bool   `long:"challenger-azdevicecode-noreadgraph" description:"Disable query user info from user graph" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_NOREADGRAPH" ini-name:"challenger-azdevicecode-noreadgraph"`
	}

	logger *log.Logger
}

func (c *authClient) Init(logger *log.Logger) error {
	c.logger = logger
	return nil
}

type aadUser struct {
	models.Userable
}

func (*aadUser) ChallengerName() string {
	return "azdevicecode"
}

func (a *aadUser) Meta() interface{} {
	return a.Userable
}

func (a *aadUser) ChallengedUsername() string {
	return *a.GetId()
}

// see https://github.com/microsoftgraph/msgraph-sdk-go
func (c *authClient) challenge(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (ssh.AdditionalChallengeContext, error) {

	cred, err := azidentity.NewDeviceCodeCredential(&azidentity.DeviceCodeCredentialOptions{
		TenantID: c.Config.TenantID,
		ClientID: c.Config.ClientID,
		UserPrompt: func(ctx context.Context, message azidentity.DeviceCodeMessage) error {
			_, err := client(conn.User(), message.Message, nil, nil)
			return err
		},
	})

	if err != nil {
		return nil, err
	}

	if c.Config.NoReadGraph {
		_, err = cred.GetToken(context.Background(), policy.TokenRequestOptions{
			Scopes: []string{c.Config.Scope},
		})

		return nil, err
	}

	auth, err := a.NewAzureIdentityAuthenticationProviderWithScopes(cred, []string{c.Config.Scope})
	if err != nil {
		return nil, err
	}

	adapter, err := msgraphsdk.NewGraphRequestAdapter(auth)
	if err != nil {
		return nil, err
	}

	gsclient := msgraphsdk.NewGraphServiceClient(adapter)
	result, err := gsclient.Me().Get()

	return &aadUser{result}, err
}

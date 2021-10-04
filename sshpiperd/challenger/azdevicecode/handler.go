package azdevicecode

import (
	"context"
	"log"
	"net/http"

	"golang.org/x/crypto/ssh"

	"github.com/Azure/azure-sdk-for-go/services/graphrbac/1.6/graphrbac"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
)

type authClient struct {
	Config struct {
		TenantID string `long:"challenger-azdevicecode-tenantid" description:"Azure AD tenant id" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_TENANTID" ini-name:"challenger-azdevicecode-tenantid"`
		ClientID string `long:"challenger-azdevicecode-clientid" description:"Azure AD client id" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_CLIENTID" ini-name:"challenger-azdevicecode-clientid"`
		// Env         string `long:"challenger-azdevicecode-env" default:"AzurePublicCloud" description:"Azure AD Cloud to request" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_ENV" ini-name:"challenger-azdevicecode-env" choice:"AzureChinaCloud" choice:"AzureGermanCloud" choice:"AzurePublicCloud" choice:"AzureUSGovernmentCloud"`
		Env         string `long:"challenger-azdevicecode-env" default:"AzurePublicCloud" description:"Azure AD Cloud to request" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_ENV" ini-name:"challenger-azdevicecode-env"`
		Resource    string `long:"challenger-azdevicecode-resource" default:"https://graph.windows.net/" description:"Resource URI to access, default is Graph API" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_RESOURCE" ini-name:"challenger-azdevicecode-resource"`
		NoReadGraph bool   `long:"challenger-azdevicecode-noreadgraph" description:"Disable query user info from user graph" env:"SSHPIPERD_CHALLENGER_AZDEVICECODE_NOREADGRAPH" ini-name:"challenger-azdevicecode-noreadgraph"`
	}

	logger      *log.Logger
	oauthConfig adal.OAuthConfig
}

func (c *authClient) Init(logger *log.Logger) error {
	c.logger = logger

	env, err := azure.EnvironmentFromName(c.Config.Env)
	if err != nil {
		return err
	}

	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, c.Config.TenantID)
	if err != nil {
		return err
	}

	c.oauthConfig = *oauthConfig

	return nil
}

type aadUser struct {
	user graphrbac.User
}

func (*aadUser) ChallengerName() string {
	return "azdevicecode"
}

func (a *aadUser) Meta() interface{} {
	return a.user
}

func (a *aadUser) ChallengedUsername() string {
	return *a.user.UserPrincipalName
}

func (c *authClient) challenge(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (ssh.AdditionalChallengeContext, error) {
	oauthClient := &http.Client{}
	deviceCode, err := adal.InitiateDeviceAuth(oauthClient, c.oauthConfig, c.Config.ClientID, c.Config.Resource)

	if err != nil {
		return nil, err
	}

	_, err = client(conn.User(), *deviceCode.Message, nil, nil)
	if err != nil {
		return nil, err
	}

	token, err := adal.WaitForUserCompletion(oauthClient, deviceCode)
	if err != nil {
		return nil, err
	}

	// skip read user info from graph api
	if c.Config.NoReadGraph {
		return nil, nil
	}

	spt, err := adal.NewServicePrincipalTokenFromManualToken(c.oauthConfig, c.Config.ClientID, c.Config.Resource, *token)
	if err != nil {
		return nil, err
	}

	signedInUserClient := graphrbac.NewSignedInUserClient(c.Config.TenantID)
	signedInUserClient.Authorizer = autorest.NewBearerAuthorizer(spt)

	result, err := signedInUserClient.Get(context.TODO())
	if err != nil {
		return nil, err
	}

	return &aadUser{user: result}, nil
}

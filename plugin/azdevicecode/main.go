package main

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	a "github.com/microsoft/kiota-authentication-azure-go"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "azdevicecode",
		Usage: "sshpiperd azure devicecode plugin, use devicecode to before ssh, see https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "tenant-id",
				Usage:    "Azure AD tenant id",
				EnvVars:  []string{"SSHPIPERD_AZDEVICECODE_TENANT_ID"},
				Required: true,
			},
			&cli.StringFlag{
				Name:     "client-id",
				Usage:    "Azure AD client id",
				EnvVars:  []string{"SSHPIPERD_AZDEVICECODE_CLIENT_ID"},
				Required: true,
			},
			&cli.BoolFlag{
				Name:    "no-read-graph",
				Usage:   "disable query user info from user graph",
				EnvVars: []string{"SSHPIPERD_AZDEVICECODE_NOREADGRAPH"},
			},
			&cli.StringFlag{
				Name:    "scope",
				Usage:   "permission scope when querying user info",
				EnvVars: []string{"SSHPIPERD_AZDEVICECODE_SCOPE"},
				Value:   "User.Read",
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			return &libplugin.SshPiperPluginConfig{
				KeyboardInteractiveCallback: func(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {

					cred, err := azidentity.NewDeviceCodeCredential(&azidentity.DeviceCodeCredentialOptions{
						TenantID: c.String("tenant-id"),
						ClientID: c.String("client-id"),
						UserPrompt: func(ctx context.Context, message azidentity.DeviceCodeMessage) error {
							_, err := client("", message.Message, "", false)
							return err
						},
					})

					if err != nil {
						return nil, err
					}

					if c.Bool("no-read-graph") {
						_, err = cred.GetToken(context.Background(), policy.TokenRequestOptions{
							Scopes: []string{c.String("scope")},
						})

						return nil, err
					}

					auth, err := a.NewAzureIdentityAuthenticationProviderWithScopes(cred, []string{c.String("scope")})
					if err != nil {
						return nil, err
					}

					adapter, err := msgraphsdk.NewGraphRequestAdapter(auth)
					if err != nil {
						return nil, err
					}

					gsclient := msgraphsdk.NewGraphServiceClient(adapter)
					result, err := gsclient.Me().Get()
					if err != nil {
						return nil, err
					}

					userId := *result.GetId()

					log.Infof("success with challenged username: %s", userId)

					return &libplugin.Upstream{
						Auth: libplugin.CreateNextPluginAuth(map[string]string{
							"UserId": *result.GetId(),
						}),
					}, nil
				},
			}, nil
		},
	})
}

module github.com/tg123/sshpiper/sshpiperd

go 1.12

replace (
	github.com/jessevdk/go-flags => github.com/tg123/go-flags v1.4.0-globalref
	golang.org/x/crypto => github.com/tg123/sshpiper.crypto v0.0.0-sshpiper-20190820
)

require (
	github.com/Azure/azure-sdk-for-go v32.5.0+incompatible
	github.com/Azure/go-autorest/autorest v0.9.0
	github.com/Azure/go-autorest/autorest/adal v0.6.0
	github.com/Azure/go-autorest/autorest/to v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/bgentry/speakeasy v0.1.0 // indirect
	github.com/dcu/go-authy v1.0.1
	github.com/go-sql-driver/mysql v1.4.1
	github.com/gojektech/heimdall v5.0.2+incompatible // indirect
	github.com/gojektech/valkyrie v0.0.0-20190210220504-8f62c1e7ba45 // indirect
	github.com/gokyle/sshkey v0.0.0-20131202145224-d32a9ef172a1
	github.com/google/uuid v1.1.1
	github.com/jessevdk/go-flags v0.0.0-00010101000000-000000000000
	github.com/jinzhu/gorm v1.9.10
	github.com/msteinert/pam v0.0.0-20190215180659-f29b9f28d6f9
	golang.org/x/crypto v0.0.0-20190325154230-a5d413f7728c
)

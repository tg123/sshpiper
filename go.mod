module github.com/tg123/sshpiper

go 1.15

replace (
	github.com/jessevdk/go-flags => github.com/tg123/go-flags v1.4.0-globalref
	golang.org/x/crypto => github.com/tg123/sshpiper.crypto v0.0.0-sshpiper-20201202
)

require (
	github.com/Azure/azure-sdk-for-go v42.2.0+incompatible
	github.com/Azure/go-autorest/autorest v0.10.1
	github.com/Azure/go-autorest/autorest/adal v0.8.3
	github.com/Azure/go-autorest/autorest/to v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/bgentry/speakeasy v0.1.0 // indirect
	github.com/dcu/go-authy v1.0.1
	github.com/denisenkom/go-mssqldb v0.0.0-20200428022330-06a60b6afbbc // indirect
	github.com/go-sql-driver/mysql v1.5.0
	github.com/gojektech/heimdall v5.0.2+incompatible // indirect
	github.com/gojektech/valkyrie v0.0.0-20190210220504-8f62c1e7ba45 // indirect
	github.com/gokyle/sshkey v0.0.0-20131202145224-d32a9ef172a1
	github.com/google/uuid v1.1.1
	github.com/jessevdk/go-flags v1.4.0
	github.com/jinzhu/gorm v1.9.12
	github.com/lib/pq v1.5.2 // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible // indirect
	github.com/msteinert/pam v0.0.0-20190215180659-f29b9f28d6f9
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.0.0-20200510223506-06a226fb4e37
	golang.org/x/sys v0.0.0-20200513112337-417ce2331b5c // indirect
	gopkg.in/yaml.v3 v3.0.0-20200506231410-2ff61e1afc86
)

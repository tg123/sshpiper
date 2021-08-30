module github.com/tg123/sshpiper

go 1.15

replace (
	github.com/jessevdk/go-flags => github.com/tg123/go-flags v1.4.0-globalref
	golang.org/x/crypto => github.com/tg123/sshpiper.crypto v0.0.0-sshpiper-20201202
)

require (
	github.com/Azure/azure-sdk-for-go v49.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.12
	github.com/Azure/go-autorest/autorest/adal v0.9.5
	github.com/Azure/go-autorest/autorest/to v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/bgentry/speakeasy v0.1.0 // indirect
	github.com/dcu/go-authy v1.0.1
	github.com/denisenkom/go-mssqldb v0.0.0-20200428022330-06a60b6afbbc // indirect
	github.com/go-sql-driver/mysql v1.5.0
	github.com/gojektech/heimdall v5.0.2+incompatible // indirect
	github.com/gojektech/valkyrie v0.0.0-20190210220504-8f62c1e7ba45 // indirect
	github.com/gokyle/sshkey v0.0.0-20131202145224-d32a9ef172a1
	github.com/google/uuid v1.1.2
	github.com/googleapis/gnostic v0.5.5 // indirect
	github.com/jessevdk/go-flags v1.4.0
	github.com/jinzhu/gorm v1.9.16
	github.com/json-iterator/go v1.1.11 // indirect
	github.com/lib/pq v1.5.2 // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible // indirect
	github.com/msteinert/pam v0.0.0-20190215180659-f29b9f28d6f9
	github.com/saturncloud/sshpipe-k8s-lib v0.0.5
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/tg123/sshkey v0.0.0-20201202190454-3bb356f89f1f
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/net v0.0.0-20210428140749-89ef3d95e781 // indirect
	golang.org/x/sys v0.0.0-20210603081109-ebe580a85c40 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v0.21.1
	k8s.io/utils v0.0.0-20210527160623-6fdb442a123b // indirect
)

replace k8s.io/client-go => k8s.io/client-go v0.21.1

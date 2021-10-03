module github.com/tg123/sshpiper

go 1.17

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
	github.com/pockost/sshpipe-k8s-lib v0.0.3
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/tg123/remotesigner v0.0.0-20210928104451-7c20285909d1
	github.com/tg123/sshkey v0.0.0-20201202190454-3bb356f89f1f
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/net v0.0.0-20210428140749-89ef3d95e781 // indirect
	golang.org/x/sys v0.0.0-20210603081109-ebe580a85c40 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/grpc v1.40.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	k8s.io/apimachinery v0.21.1
	k8s.io/client-go v0.21.1
	k8s.io/utils v0.0.0-20210527160623-6fdb442a123b // indirect
)

require (
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.0 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/form3tech-oss/jwt-go v3.2.2+incompatible // indirect
	github.com/go-logr/logr v0.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.5 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d // indirect
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d // indirect
	golang.org/x/text v0.3.6 // indirect
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba // indirect
	google.golang.org/genproto v0.0.0-20201019141844-1ed22bb0c154 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/api v0.21.1 // indirect
	k8s.io/klog/v2 v2.8.0 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.1.0 // indirect
	sigs.k8s.io/yaml v1.2.0 // indirect
)

replace k8s.io/client-go => k8s.io/client-go v0.21.1

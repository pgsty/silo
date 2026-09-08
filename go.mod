module github.com/minio/minio

go 1.27.1

// Console and MC retain their historical module paths for best-effort upstream
// compatibility. Pin the maintained PGSTY implementations used by SILO.
replace github.com/minio/console => github.com/pgsty/silo-console v0.0.0-20260908011343-b39a84ada5e8

replace github.com/minio/mc => github.com/pgsty/mc v0.0.0-20260903063637-a2ef95c035d9

// v22.7.0 does not compile on NetBSD because its unix implementation uses
// CLOCK_MONOTONIC, which is unavailable there. Keep the last portable release
// until go-systemd ships the upstream fix.
replace github.com/coreos/go-systemd/v22 => github.com/coreos/go-systemd/v22 v22.6.0

// Install tools using 'go install tool'.
tool (
	github.com/tinylib/msgp
	golang.org/x/tools/cmd/stringer
)

require (
	aead.dev/mtls v0.3.0
	cloud.google.com/go/storage v1.61.3
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.22.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.14.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.6.4
	github.com/IBM/sarama v1.45.1
	github.com/alecthomas/participle v0.7.1
	github.com/beevik/ntp v1.5.0
	github.com/buger/jsonparser v1.1.2
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/cheggaaa/pb v1.0.30
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/coreos/go-systemd/v22 v22.7.0
	github.com/cosnicolaou/pbzip2 v1.0.6
	github.com/dchest/siphash v1.2.3
	github.com/dustin/go-humanize v1.0.1
	github.com/eclipse/paho.mqtt.golang v1.5.1
	github.com/elastic/go-elasticsearch/v7 v7.17.10
	github.com/fatih/color v1.19.0
	github.com/felixge/fgprof v0.9.5
	github.com/fraugster/parquet-go v0.12.0
	github.com/go-ldap/ldap/v3 v3.4.14
	github.com/go-openapi/loads v0.25.2
	github.com/go-sql-driver/mysql v1.9.3
	github.com/gobwas/ws v1.4.0
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/gomodule/redigo v1.9.3
	github.com/google/uuid v1.6.0
	github.com/inconshreveable/mousetrap v1.1.0
	github.com/json-iterator/go v1.1.12
	github.com/klauspost/compress v1.20.0
	github.com/klauspost/cpuid/v2 v2.4.0
	github.com/klauspost/filepathx v1.1.1
	github.com/klauspost/pgzip v1.2.6
	github.com/klauspost/readahead v1.4.0
	github.com/klauspost/reedsolomon v1.13.3
	github.com/lib/pq v1.10.9
	github.com/lithammer/shortuuid/v4 v4.2.0
	github.com/miekg/dns v1.1.73
	github.com/minio/cli v1.24.2
	github.com/minio/console v1.7.6
	github.com/minio/csvparser v1.0.0
	github.com/minio/dnscache v0.1.1
	github.com/minio/dperf v0.7.1
	github.com/minio/highwayhash v1.0.4
	github.com/minio/kms-go/kes v0.3.1
	github.com/minio/kms-go/kms v0.6.0
	github.com/minio/madmin-go/v3 v3.0.110
	github.com/minio/minio-go/v7 v7.3.1-0.20260828014306-0e78d3f18efe
	github.com/minio/mux v1.10.1
	github.com/minio/selfupdate v0.6.0
	github.com/minio/simdjson-go v0.4.5
	github.com/minio/sio v0.4.3
	github.com/minio/xxml v0.0.3
	github.com/minio/zipindex v0.5.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/nats-io/nats-server/v2 v2.11.15
	github.com/nats-io/nats.go v1.49.0
	github.com/nats-io/stan.go v0.10.4
	github.com/ncw/directio v1.0.5
	github.com/nsqio/go-nsq v1.1.0
	github.com/pgsty/silo-pkg/v3 v3.13.2
	github.com/philhofer/fwd v1.2.0
	github.com/pierrec/lz4/v4 v4.1.29
	github.com/pkg/errors v0.9.1
	github.com/pkg/sftp v1.13.11
	github.com/pkg/xattr v0.4.12
	github.com/prometheus/client_golang v1.24.1
	github.com/prometheus/client_model v0.6.3
	github.com/prometheus/common v0.71.0
	github.com/prometheus/procfs v0.22.0
	github.com/puzpuzpuz/xsync/v3 v3.5.1
	github.com/rabbitmq/amqp091-go v1.10.0
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9
	github.com/rs/cors v1.11.1
	github.com/secure-io/sio-go v0.3.1
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/tinylib/msgp v1.6.4
	github.com/valyala/bytebufferpool v1.0.0
	github.com/xdg/scram v1.0.5
	github.com/zeebo/xxh3 v1.1.0
	go.etcd.io/etcd/api/v3 v3.7.1
	go.etcd.io/etcd/client/v3 v3.7.1
	go.uber.org/atomic v1.11.0
	go.uber.org/zap v1.28.0
	go.yaml.in/yaml/v3 v3.0.5
	goftp.io/server/v2 v2.0.3
	golang.org/x/crypto v0.56.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	golang.org/x/time v0.15.0
	google.golang.org/api v0.290.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	aead.dev/mem v0.2.0 // indirect
	aead.dev/minisign v0.3.0 // indirect
	cel.dev/expr v0.25.2 // indirect
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.20.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.5.3 // indirect
	cloud.google.com/go/monitoring v1.24.3 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.12.0 // indirect
	github.com/Azure/go-ntlmssp v0.1.1 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.7.2 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.33.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.55.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.55.0 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d // indirect
	github.com/antithesishq/antithesis-sdk-go v0.6.0-default-no-op // indirect
	github.com/apache/thrift v0.24.0 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/charmbracelet/bubbles v1.0.0 // indirect
	github.com/charmbracelet/bubbletea v1.3.10 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/harmonica v0.2.0 // indirect
	github.com/charmbracelet/lipgloss v1.1.0 // indirect
	github.com/charmbracelet/x/ansi v0.11.8 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/eapache/go-resiliency v1.7.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20230731223053-c322873962e3 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.37.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.3 // indirect
	github.com/erikgeiser/coninput v0.0.0-20211004153227-1c3628e74d0f // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/analysis v0.26.2 // indirect
	github.com/go-openapi/errors v0.22.8 // indirect
	github.com/go-openapi/jsonpointer v1.0.0 // indirect
	github.com/go-openapi/jsonreference v1.0.1 // indirect
	github.com/go-openapi/runtime v0.33.1 // indirect
	github.com/go-openapi/runtime/server-middleware v0.33.1 // indirect
	github.com/go-openapi/spec v1.0.0 // indirect
	github.com/go-openapi/strfmt v0.27.0 // indirect
	github.com/go-openapi/swag v0.29.1 // indirect
	github.com/go-openapi/swag/cmdutils v0.29.1 // indirect
	github.com/go-openapi/swag/conv v0.29.1 // indirect
	github.com/go-openapi/swag/fileutils v0.29.1 // indirect
	github.com/go-openapi/swag/jsonutils v0.29.1 // indirect
	github.com/go-openapi/swag/loading v0.29.1 // indirect
	github.com/go-openapi/swag/mangling v0.29.1 // indirect
	github.com/go-openapi/swag/netutils v0.29.1 // indirect
	github.com/go-openapi/swag/pools v0.29.1 // indirect
	github.com/go-openapi/swag/stringutils v0.29.1 // indirect
	github.com/go-openapi/swag/typeutils v0.29.1 // indirect
	github.com/go-openapi/swag/yamlutils v0.29.1 // indirect
	github.com/go-openapi/validate v0.26.5 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/pprof v0.0.0-20260709232956-b9395ee17fa0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.18 // indirect
	github.com/googleapis/gax-go/v2 v2.23.0 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/grafana/regexp v0.0.0-20250905093917-f7b3be9d1853 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jedib0t/go-pretty/v6 v6.8.3 // indirect
	github.com/jessevdk/go-flags v1.6.1 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.4.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.6 // indirect
	github.com/lestrrat-go/jwx/v3 v3.2.0 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.4.1 // indirect
	github.com/lufia/plan9stats v0.0.0-20260802145828-341c2f0c90b5 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-ieproxy v0.0.12 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mattn/go-localereader v0.0.1 // indirect
	github.com/mattn/go-runewidth v0.0.29 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/minio/colorjson v1.0.8 // indirect
	github.com/minio/crc64nvme v1.1.1 // indirect
	github.com/minio/filepath v1.0.0 // indirect
	github.com/minio/mc v0.0.0-20251106162529-77f82e18b540 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	// Legacy minio/colorjson and minio/dperf code still imports pkg/console.
	// SILO source imports github.com/pgsty/silo-pkg/v3 directly instead.
	github.com/minio/pkg/v3 v3.6.1 // indirect
	github.com/minio/websocket v1.6.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/muesli/ansi v0.0.0-20230316100256-276c6243b2f6 // indirect
	github.com/muesli/cancelreader v0.2.2 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nats-io/jwt/v2 v2.8.1 // indirect
	github.com/nats-io/nats-streaming-server v0.24.6 // indirect
	github.com/nats-io/nkeys v0.4.15 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/olekukonko/tablewriter v0.0.5 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/posener/complete v1.2.3 // indirect
	github.com/power-devops/perfstat v0.0.0-20260805114148-88456608a4f6 // indirect
	github.com/prometheus/prom2json v1.5.0 // indirect
	github.com/prometheus/prometheus v0.314.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rjeczalik/notify v0.9.3 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/safchain/ethtool v0.7.0 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/shoenig/go-m1cpu v0.2.2 // indirect
	github.com/spiffe/go-spiffe/v2 v2.7.0 // indirect
	github.com/tidwall/gjson v1.19.0 // indirect
	github.com/tidwall/match v1.2.0 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/unrolled/secure v1.17.0 // indirect
	github.com/valyala/fastjson v1.6.10 // indirect
	github.com/vbauerster/cupwriter v0.0.4 // indirect
	github.com/vbauerster/mpb/v8 v8.16.1 // indirect
	github.com/xdg/stringprep v1.0.3 // indirect
	github.com/xo/terminfo v1.0.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.7.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.44.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.70.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.70.0 // indirect
	go.opentelemetry.io/otel v1.45.0 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/sdk v1.45.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/trace v1.45.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/mod v0.40.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	google.golang.org/genproto v0.0.0-20260319201613-d00831a3d3e7 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260831171406-18b4a7587f8a // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260831171406-18b4a7587f8a // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/ini.v1 v1.67.3 // indirect
)

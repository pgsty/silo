#!/bin/sh

# Install a lifecycle XML document without an SDK normalizing away Silo's
# AccessTransition and AccessTierQuota extension elements.
set -eu

if [ "$#" -ne 4 ]; then
	echo "usage: AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... $0 ENDPOINT BUCKET REGION LIFECYCLE_XML" >&2
	exit 2
fi

endpoint=$1
bucket=$2
region=$3
lifecycle_file=$4

: "$AWS_ACCESS_KEY_ID"
: "$AWS_SECRET_ACCESS_KEY"

if [ ! -r "$lifecycle_file" ]; then
	echo "cannot read lifecycle document: $lifecycle_file" >&2
	exit 2
fi

content_md5=$(openssl dgst -md5 -binary "$lifecycle_file" | openssl base64)
endpoint=$(printf '%s' "$endpoint" | sed 's:/*$::')

curl --fail-with-body --silent --show-error \
	--request PUT \
	--aws-sigv4 "aws:amz:$region:s3" \
	--user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
	--header "Content-MD5: $content_md5" \
	--header "Content-Type: application/xml" \
	--data-binary "@$lifecycle_file" \
	"$endpoint/$bucket?lifecycle"

echo "installed lifecycle configuration on $bucket"

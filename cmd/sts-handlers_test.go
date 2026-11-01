// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/klauspost/compress/zip"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	cr "github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/minio/minio-go/v7/pkg/tags"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/ldap"
	"github.com/pgsty/silo-pkg/v3/policy"
)

func runAllIAMSTSTests(suite *TestSuiteIAM, c *check) {
	suite.SetUpSuite(c)
	// The STS for root test needs to be the first one after setup.
	suite.TestSTSForRoot(c)
	suite.TestSTS(c)
	suite.TestSTSPrivilegeEscalationBug2_2025_10_15(c, true)
	suite.TestSTSPrivilegeEscalationBug2_2025_10_15(c, false)
	suite.TestSTSWithDenyDeleteVersion(c)
	suite.TestSTSWithTags(c)
	suite.TestSTSServiceAccountsWithUsername(c)
	suite.TestSTSWithGroupPolicy(c)
	suite.TestSTSTokenRevoke(c)
	suite.TearDownSuite(c)
}

func TestIAMInternalIDPSTSServerSuite(t *testing.T) {
	baseTestCases := []TestSuiteCommon{
		// Init and run test on ErasureSD backend with signature v4.
		{serverType: "ErasureSD", signer: signerV4},
		// Init and run test on ErasureSD backend, with tls enabled.
		{serverType: "ErasureSD", signer: signerV4, secure: true},
		// Init and run test on Erasure backend.
		{serverType: "Erasure", signer: signerV4},
		// Init and run test on ErasureSet backend.
		{serverType: "ErasureSet", signer: signerV4},
	}
	testCases := []*TestSuiteIAM{}
	for _, bt := range baseTestCases {
		testCases = append(testCases,
			newTestSuiteIAM(bt, false),
			newTestSuiteIAM(bt, true),
		)
	}
	for i, testCase := range testCases {
		etcdStr := ""
		if testCase.withEtcdBackend {
			etcdStr = " (with etcd backend)"
		}
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s%s", i+1, testCase.serverType, etcdStr),
			func(t *testing.T) {
				runAllIAMSTSTests(testCase, &check{t, testCase.serverType})
			},
		)
	}
}

func (s *TestSuiteIAM) TestSTSServiceAccountsWithUsername(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := "dillon-bucket"
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Create policy
	policy := "mypolicy-username"
	policyBytes := []byte(`{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:*"
   ],
   "Resource": [
    "arn:aws:s3:::${aws:username}-*"
   ]
  }
 ]
}`)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	if err = s.adm.AddUser(ctx, "dillon", "dillon-123"); err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	_, err = s.adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{
		Policies: []string{policy},
		User:     "dillon",
	})
	if err != nil {
		c.Fatalf("Unable to attach policy: %v", err)
	}

	assumeRole := cr.STSAssumeRole{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		Options: cr.STSAssumeRoleOptions{
			AccessKey: "dillon",
			SecretKey: "dillon-123",
			Location:  "",
		},
	}

	value, err := assumeRole.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	// Check that the LDAP sts cred is actually working.
	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Create an madmin client with user creds
	userAdmClient, err := madmin.NewWithOptions(s.endpoint, &madmin.Options{
		Creds:  cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure: s.secure,
	})
	if err != nil {
		c.Fatalf("Err creating user admin client: %v", err)
	}
	userAdmClient.SetCustomTransport(s.TestSuiteCommon.client.Transport)

	// Create svc acc
	cr := c.mustCreateSvcAccount(ctx, value.AccessKeyID, userAdmClient)

	svcClient := s.getUserClient(c, cr.AccessKey, cr.SecretKey, "")

	// 1. Check S3 access for service account ListObjects()
	c.mustListObjects(ctx, svcClient, bucket)

	// 2. Check S3 access for upload
	c.mustUpload(ctx, svcClient, bucket)

	// 3. Check S3 access for download
	c.mustDownload(ctx, svcClient, bucket)
}

func (s *TestSuiteIAM) TestSTSWithDenyDeleteVersion(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{ObjectLocking: true})
	if err != nil {
		c.Fatalf("bucket creat error: %v", err)
	}

	// Create policy, user and associate policy
	policy := "mypolicy"
	policyBytes := fmt.Appendf(nil, `{
  "Version": "2012-10-17",
  "Statement": [
   {
    "Sid": "ObjectActionsRW",
    "Effect": "Allow",
    "Action": [
     "s3:PutObject",
     "s3:PutObjectTagging",
     "s3:AbortMultipartUpload",
     "s3:DeleteObject",
     "s3:GetObject",
     "s3:GetObjectTagging",
     "s3:GetObjectVersion",
     "s3:ListMultipartUploadParts"
    ],
    "Resource": [
     "arn:aws:s3:::%s/*"
    ]
   },
   {
    "Sid": "DenyDeleteVersionAction",
    "Effect": "Deny",
    "Action": [
     "s3:DeleteObjectVersion"
    ],
    "Resource": [
     "arn:aws:s3:::%s/*"
    ]
   }
  ]
 }
`, bucket, bucket)

	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	accessKey, secretKey := mustGenerateCredentials(c)
	err = s.adm.SetUser(ctx, accessKey, secretKey, madmin.AccountEnabled)
	if err != nil {
		c.Fatalf("Unable to set user: %v", err)
	}

	_, err = s.adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{
		Policies: []string{policy},
		User:     accessKey,
	})
	if err != nil {
		c.Fatalf("Unable to attach policy: %v", err)
	}

	// confirm that the user is able to access the bucket
	uClient := s.getUserClient(c, accessKey, secretKey, "")
	versions := c.mustUploadReturnVersions(ctx, uClient, bucket)
	c.mustNotDelete(ctx, uClient, bucket, versions[0])

	assumeRole := cr.STSAssumeRole{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		Options: cr.STSAssumeRoleOptions{
			AccessKey: accessKey,
			SecretKey: secretKey,
			Location:  "",
		},
	}

	value, err := assumeRole.Retrieve()
	if err != nil {
		c.Fatalf("err calling assumeRole: %v", err)
	}

	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	versions = c.mustUploadReturnVersions(ctx, minioClient, bucket)
	c.mustNotDelete(ctx, minioClient, bucket, versions[0])
}

func (s *TestSuiteIAM) TestSTSPrivilegeEscalationBug2_2025_10_15(c *check, forRoot bool) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	for i := range 3 {
		err := s.client.MakeBucket(ctx, fmt.Sprintf("bucket%d", i+1), minio.MakeBucketOptions{})
		if err != nil {
			c.Fatalf("bucket create error: %v", err)
		}
		defer func(i int) {
			_ = s.client.RemoveBucket(ctx, fmt.Sprintf("bucket%d", i+1))
		}(i)
	}

	allow2BucketsPolicyBytes := []byte(`{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ListBucket1AndBucket2",
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": ["arn:aws:s3:::bucket1", "arn:aws:s3:::bucket2"]
        },
        {
            "Sid": "ReadWriteBucket1AndBucket2Objects",
            "Effect": "Allow",
            "Action": [
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:GetObject",
                "s3:GetObjectVersion",
                "s3:PutObject"
            ],
            "Resource": ["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/*"]
        }
    ]
}`)

	var value cr.Value
	var err error
	if forRoot {
		assumeRole := cr.STSAssumeRole{
			Client:      s.TestSuiteCommon.client,
			STSEndpoint: s.endPoint,
			Options: cr.STSAssumeRoleOptions{
				AccessKey: globalActiveCred.AccessKey,
				SecretKey: globalActiveCred.SecretKey,
				Policy:    string(allow2BucketsPolicyBytes),
			},
		}
		value, err = assumeRole.Retrieve()
		if err != nil {
			c.Fatalf("err calling assumeRole: %v", err)
		}
	} else {
		// Create a regular user and attach consoleAdmin policy
		err := s.adm.AddUser(ctx, "foobar", "foobar123")
		if err != nil {
			c.Fatalf("could not create user")
		}

		_, err = s.adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{
			Policies: []string{"consoleAdmin"},
			User:     "foobar",
		})
		if err != nil {
			c.Fatalf("could not attach policy")
		}

		assumeRole := cr.STSAssumeRole{
			Client:      s.TestSuiteCommon.client,
			STSEndpoint: s.endPoint,
			Options: cr.STSAssumeRoleOptions{
				AccessKey: "foobar",
				SecretKey: "foobar123",
				Policy:    string(allow2BucketsPolicyBytes),
			},
		}
		value, err = assumeRole.Retrieve()
		if err != nil {
			c.Fatalf("err calling assumeRole: %v", err)
		}
	}
	restrictedClient := s.getUserClient(c, value.AccessKeyID, value.SecretAccessKey, value.SessionToken)

	buckets, err := restrictedClient.ListBuckets(ctx)
	if err != nil {
		c.Fatalf("err fetching buckets %s", err)
	}
	if len(buckets) != 2 || buckets[0].Name != "bucket1" || buckets[1].Name != "bucket2" {
		c.Fatalf("restricted STS account should only have access to bucket1 and bucket2")
	}

	// Try to escalate privileges
	restrictedAdmClient := s.getAdminClient(c, value.AccessKeyID, value.SecretAccessKey, value.SessionToken)
	_, err = restrictedAdmClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
		AccessKey: "newroot",
		SecretKey: "newroot123",
	})
	if err == nil {
		c.Fatalf("restricted STS account was able to create service account bypassing sub-policy!")
	}
}

func (s *TestSuiteIAM) TestSTSWithTags(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	object := getRandomObjectName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket creat error: %v", err)
	}

	// Create policy, user and associate policy
	policy := "mypolicy"
	policyBytes := fmt.Appendf(nil, `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect":     "Allow",
      "Action":     "s3:GetObject",
      "Resource":    "arn:aws:s3:::%s/*",
      "Condition": {  "StringEquals": {"s3:ExistingObjectTag/security": "public" } }
    },
    {
      "Effect":     "Allow",
      "Action":     "s3:DeleteObjectTagging",
      "Resource":    "arn:aws:s3:::%s/*",
      "Condition": {  "StringEquals": {"s3:ExistingObjectTag/security": "public" } }
    },
    {
      "Effect":     "Allow",
      "Action":     "s3:PutObjectTagging",
      "Resource":    "arn:aws:s3:::%s/*",
      "Condition": { "StringEquals": {
        "s3:ExistingObjectTag/virus": "true",
        "s3:RequestObjectTag/security": "public"
      } }
    },
    {
      "Effect":     "Allow",
      "Action":     "s3:DeleteObject",
      "Resource":    "arn:aws:s3:::%s/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject"
      ],
      "Resource": [
        "arn:aws:s3:::%s/*"
      ],
      "Condition": {
        "StringEquals": {
          "s3:RequestObjectTag/security": "public"
        },
        "ForAllValues:StringLike": {
          "s3:RequestObjectTagKeys": [
            "security",
            "virus"
          ]
        }
      }
    }
  ]
}`, bucket, bucket, bucket, bucket, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	accessKey, secretKey := mustGenerateCredentials(c)
	err = s.adm.SetUser(ctx, accessKey, secretKey, madmin.AccountEnabled)
	if err != nil {
		c.Fatalf("Unable to set user: %v", err)
	}

	_, err = s.adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{
		Policies: []string{policy},
		User:     accessKey,
	})
	if err != nil {
		c.Fatalf("Unable to attach policy: %v", err)
	}

	// confirm that the user is able to access the bucket
	uClient := s.getUserClient(c, accessKey, secretKey, "")
	queryObject := object + "-query-tags"
	queryTags := "security=public&virus=true"
	// Query storage-class values were historically accepted without the strict
	// header validation. Pin that compatibility while proving they are consumed.
	presignedPut, err := uClient.Presign(ctx, http.MethodPut, bucket, queryObject, time.Minute, url.Values{
		"x-amz-storage-class": {"CUSTOM_COMPAT"},
		"x-amz-tagging":       {queryTags},
	})
	if err != nil {
		c.Fatalf("unable to presign query-tagged upload: %v", err)
	}
	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, presignedPut.String(), bytes.NewReader([]byte("stuff")))
	if err != nil {
		c.Fatalf("unable to build query-tagged upload: %v", err)
	}
	putResp, err := s.TestSuiteCommon.client.Do(putReq)
	if err != nil {
		c.Fatalf("query-tagged upload failed: %v", err)
	}
	putBody, readErr := io.ReadAll(putResp.Body)
	putResp.Body.Close()
	if readErr != nil {
		c.Fatalf("unable to read query-tagged upload response: %v", readErr)
	}
	if putResp.StatusCode != http.StatusOK {
		c.Fatalf("query-tagged upload returned %s: %s", putResp.Status, putBody)
	}
	storedTags, err := s.client.GetObjectTagging(ctx, bucket, queryObject, minio.GetObjectTaggingOptions{})
	if err != nil {
		c.Fatalf("unable to read persisted query tags: %v", err)
	}
	if got := storedTags.ToMap(); got["security"] != "public" || got["virus"] != "true" {
		c.Fatalf("query tags were not persisted: %v", got)
	}
	queryObjectInfo, err := s.testServer.Obj.GetObjectInfo(ctx, bucket, queryObject, ObjectOptions{})
	if err != nil {
		c.Fatalf("unable to inspect query-tagged object: %v", err)
	}
	if queryObjectInfo.StorageClass != "CUSTOM_COMPAT" {
		c.Fatalf("query storage class was not persisted: %q", queryObjectInfo.StorageClass)
	}
	c.mustGetObject(ctx, uClient, bucket, queryObject)

	multipartObject := object + "-multipart-query-tags"
	presignedMultipart, err := uClient.Presign(ctx, http.MethodPost, bucket, multipartObject, time.Minute, url.Values{
		"uploads":       {""},
		"x-amz-tagging": {queryTags},
	})
	if err != nil {
		c.Fatalf("unable to presign query-tagged multipart upload: %v", err)
	}
	multipartReq, err := http.NewRequestWithContext(ctx, http.MethodPost, presignedMultipart.String(), nil)
	if err != nil {
		c.Fatalf("unable to build query-tagged multipart upload: %v", err)
	}
	multipartResp, err := s.TestSuiteCommon.client.Do(multipartReq)
	if err != nil {
		c.Fatalf("query-tagged multipart upload failed: %v", err)
	}
	multipartBody, readErr := io.ReadAll(multipartResp.Body)
	multipartResp.Body.Close()
	if readErr != nil {
		c.Fatalf("unable to read query-tagged multipart response: %v", readErr)
	}
	if multipartResp.StatusCode != http.StatusOK {
		c.Fatalf("query-tagged multipart upload returned %s: %s", multipartResp.Status, multipartBody)
	}
	var multipartResult InitiateMultipartUploadResponse
	if err = xml.Unmarshal(multipartBody, &multipartResult); err != nil || multipartResult.UploadID == "" {
		c.Fatalf("invalid query-tagged multipart response: uploadID=%q err=%v", multipartResult.UploadID, err)
	}
	if err = (minio.Core{Client: s.client}).AbortMultipartUpload(ctx, bucket, multipartObject, multipartResult.UploadID); err != nil {
		c.Fatalf("unable to clean up query-tagged multipart upload: %v", err)
	}

	c.mustPutObjectWithTags(ctx, uClient, bucket, object)
	c.mustGetObject(ctx, uClient, bucket, object)
	objectInfo, err := s.client.StatObject(ctx, bucket, object, minio.StatObjectOptions{})
	if err != nil {
		c.Fatalf("unable to stat object for conditional GET: %v", err)
	}
	presignedGet, err := uClient.PresignedGetObject(ctx, bucket, object, time.Minute, nil)
	if err != nil {
		c.Fatalf("unable to presign conditional GET: %v", err)
	}
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, presignedGet.String(), nil)
	if err != nil {
		c.Fatalf("unable to build conditional GET: %v", err)
	}
	getReq.Header.Set(xhttp.IfNoneMatch, `"`+objectInfo.ETag+`"`)
	getResp := httptest.NewRecorder()
	s.testServer.Server.Config.Handler.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusNotModified || getResp.Body.Len() != 0 {
		c.Fatalf("conditional GET returned status %d with body %q", getResp.Code, getResp.Body.String())
	}
	replacementTags, err := tags.NewTags(map[string]string{"security": "public", "reviewed": "yes"}, true)
	if err != nil {
		c.Fatalf("unable to build replacement tags: %v", err)
	}
	if err = uClient.PutObjectTagging(ctx, bucket, object, replacementTags, minio.PutObjectTaggingOptions{}); err != nil {
		c.Fatalf("user is unable to replace object tags: %v", err)
	}

	assumeRole := cr.STSAssumeRole{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		Options: cr.STSAssumeRoleOptions{
			AccessKey: accessKey,
			SecretKey: secretKey,
			Location:  "",
		},
	}

	value, err := assumeRole.Retrieve()
	if err != nil {
		c.Fatalf("err calling assumeRole: %v", err)
	}

	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate sts creds can access the object
	c.mustPutObjectWithTags(ctx, minioClient, bucket, object)
	c.mustGetObject(ctx, minioClient, bucket, object)
	c.mustHeadObject(ctx, minioClient, bucket, object, 2)

	// Validate that the client can remove objects
	if err = minioClient.RemoveObjectTagging(ctx, bucket, object, minio.RemoveObjectTaggingOptions{}); err != nil {
		c.Fatalf("user is unable to delete the object tags: %v", err)
	}

	if err = minioClient.RemoveObject(ctx, bucket, object, minio.RemoveObjectOptions{}); err != nil {
		c.Fatalf("user is unable to delete the object: %v", err)
	}
	if err = minioClient.RemoveObject(ctx, bucket, queryObject, minio.RemoveObjectOptions{}); err != nil {
		c.Fatalf("user is unable to delete the query-tagged object: %v", err)
	}
}

func (s *TestSuiteIAM) TestSTS(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket creat error: %v", err)
	}

	// Create policy, user and associate policy
	policy := "mypolicy"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	accessKey, secretKey := mustGenerateCredentials(c)
	err = s.adm.SetUser(ctx, accessKey, secretKey, madmin.AccountEnabled)
	if err != nil {
		c.Fatalf("Unable to set user: %v", err)
	}

	_, err = s.adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{
		Policies: []string{policy},
		User:     accessKey,
	})
	if err != nil {
		c.Fatalf("Unable to attach policy: %v", err)
	}

	// confirm that the user is able to access the bucket
	uClient := s.getUserClient(c, accessKey, secretKey, "")
	c.mustListObjects(ctx, uClient, bucket)

	assumeRole := cr.STSAssumeRole{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		Options: cr.STSAssumeRoleOptions{
			AccessKey: accessKey,
			SecretKey: secretKey,
			Location:  "",
		},
	}

	value, err := assumeRole.Retrieve()
	if err != nil {
		c.Fatalf("err calling assumeRole: %v", err)
	}

	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that the client cannot remove any objects
	err = minioClient.RemoveObject(ctx, bucket, "someobject", minio.RemoveObjectOptions{})
	if err.Error() != "Access Denied." {
		c.Fatalf("unexpected non-access-denied err: %v", err)
	}
}

func (s *TestSuiteIAM) TestSTSWithGroupPolicy(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket creat error: %v", err)
	}

	// Create policy, user and associate policy
	policy := "mypolicy"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	accessKey, secretKey := mustGenerateCredentials(c)
	err = s.adm.SetUser(ctx, accessKey, secretKey, madmin.AccountEnabled)
	if err != nil {
		c.Fatalf("Unable to set user: %v", err)
	}

	// confirm that the user is unable to access the bucket - we have not
	// yet set any policy
	uClient := s.getUserClient(c, accessKey, secretKey, "")
	c.mustNotListObjects(ctx, uClient, bucket)

	err = s.adm.UpdateGroupMembers(ctx, madmin.GroupAddRemove{
		Group:   "test-group",
		Members: []string{accessKey},
	})
	if err != nil {
		c.Fatalf("unable to add user to group: %v", err)
	}

	_, err = s.adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{
		Policies: []string{policy},
		Group:    "test-group",
	})
	if err != nil {
		c.Fatalf("Unable to attach policy: %v", err)
	}

	// confirm that the user is able to access the bucket - permission comes
	// from group.
	c.mustListObjects(ctx, uClient, bucket)

	// Create STS user.
	assumeRole := cr.STSAssumeRole{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		Options: cr.STSAssumeRoleOptions{
			AccessKey: accessKey,
			SecretKey: secretKey,
			Location:  "",
		},
	}
	value, err := assumeRole.Retrieve()
	if err != nil {
		c.Fatalf("err calling assumeRole: %v", err)
	}

	// Check that STS user client has access coming from parent user's
	// group.
	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that the client cannot remove any objects
	err = minioClient.RemoveObject(ctx, bucket, "someobject", minio.RemoveObjectOptions{})
	if err.Error() != "Access Denied." {
		c.Fatalf("unexpected non-access-denied err: %v", err)
	}
}

// TestSTSForRoot - needs to be the first test after server setup due to the
// buckets list check.
func (s *TestSuiteIAM) TestSTSForRoot(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	assumeRole := cr.STSAssumeRole{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		Options: cr.STSAssumeRoleOptions{
			AccessKey: globalActiveCred.AccessKey,
			SecretKey: globalActiveCred.SecretKey,
			Location:  "",
		},
	}

	value, err := assumeRole.Retrieve()
	if err != nil {
		c.Fatalf("err calling assumeRole: %v", err)
	}

	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that a bucket can be created
	bucket2 := getRandomBucketName()
	err = minioClient.MakeBucket(ctx, bucket2, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket creat error: %v", err)
	}

	// Validate that admin APIs can be called - create an madmin client with
	// user creds
	userAdmClient, err := madmin.NewWithOptions(s.endpoint, &madmin.Options{
		Creds:  cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure: s.secure,
	})
	if err != nil {
		c.Fatalf("Err creating user admin client: %v", err)
	}
	userAdmClient.SetCustomTransport(s.TestSuiteCommon.client.Transport)

	time.Sleep(2 * time.Second) // wait for listbuckets cache to be invalidated

	accInfo, err := userAdmClient.AccountInfo(ctx, madmin.AccountOpts{})
	if err != nil {
		c.Fatalf("root user STS should be able to get account info: %v", err)
	}

	gotBuckets := set.NewStringSet()
	for _, b := range accInfo.Buckets {
		gotBuckets.Add(b.Name)
		if !b.Access.Read || !b.Access.Write {
			c.Fatalf("root user should have read and write access to bucket: %v", b.Name)
		}
	}
	shouldHaveBuckets := set.CreateStringSet(bucket2, bucket)
	if !gotBuckets.Equals(shouldHaveBuckets) {
		c.Fatalf("root user should have access to all buckets")
	}

	// This must fail.
	if err := userAdmClient.AddUser(ctx, globalActiveCred.AccessKey, globalActiveCred.SecretKey); err == nil {
		c.Fatal("AddUser() for root credential must fail via root STS creds")
	}
}

// TestSTSTokenRevoke - tests the token revoke API
func (s *TestSuiteIAM) TestSTSTokenRevoke(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Create policy, user and associate policy
	policy := "mypolicy"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	accessKey, secretKey := mustGenerateCredentials(c)
	err = s.adm.SetUser(ctx, accessKey, secretKey, madmin.AccountEnabled)
	if err != nil {
		c.Fatalf("Unable to set user: %v", err)
	}

	_, err = s.adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{
		Policies: []string{policy},
		User:     accessKey,
	})
	if err != nil {
		c.Fatalf("Unable to attach policy: %v", err)
	}

	cases := []struct {
		tokenType  string
		fullRevoke bool
		selfRevoke bool
	}{
		{"", true, false},        // Case 1
		{"", true, true},         // Case 2
		{"type-1", false, false}, // Case 3
		{"type-2", false, true},  // Case 4
		{"type-2", true, true},   // Case 5 - repeat type 2 to ensure previous revoke does not affect it.
	}

	for i, tc := range cases {
		// Create STS user.
		assumeRole := cr.STSAssumeRole{
			Client:      s.TestSuiteCommon.client,
			STSEndpoint: s.endPoint,
			Options: cr.STSAssumeRoleOptions{
				AccessKey:       accessKey,
				SecretKey:       secretKey,
				TokenRevokeType: tc.tokenType,
			},
		}

		value, err := assumeRole.Retrieve()
		if err != nil {
			c.Fatalf("err calling assumeRole: %v", err)
		}

		minioClient, err := minio.New(s.endpoint, &minio.Options{
			Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
			Secure:    s.secure,
			Transport: s.TestSuiteCommon.client.Transport,
		})
		if err != nil {
			c.Fatalf("Error initializing client: %v", err)
		}

		// Validate that the client from sts creds can access the bucket.
		c.mustListObjects(ctx, minioClient, bucket)

		// Set up revocation
		user := accessKey
		tokenType := tc.tokenType
		reqAdmClient := s.adm
		if tc.fullRevoke {
			tokenType = ""
		}
		if tc.selfRevoke {
			user = ""
			tokenType = ""
			reqAdmClient, err = madmin.NewWithOptions(s.endpoint, &madmin.Options{
				Creds:  cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
				Secure: s.secure,
			})
			if err != nil {
				c.Fatalf("Err creating user admin client: %v", err)
			}
			reqAdmClient.SetCustomTransport(s.TestSuiteCommon.client.Transport)
		}

		err = reqAdmClient.RevokeTokens(ctx, madmin.RevokeTokensReq{
			User:            user,
			TokenRevokeType: tokenType,
			FullRevoke:      tc.fullRevoke,
		})
		if err != nil {
			c.Fatalf("Case %d: unexpected error: %v", i+1, err)
		}

		// Validate that the client cannot access the bucket after revocation.
		c.mustNotListObjects(ctx, minioClient, bucket)
	}
}

// SetUpLDAP - expects to setup an LDAP test server using the test LDAP
// container and canned data from https://github.com/minio/minio-ldap-testing
func (s *TestSuiteIAM) SetUpLDAP(c *check, serverAddr string) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	configCmds := []string{
		"identity_ldap",
		fmt.Sprintf("server_addr=%s", serverAddr),
		"server_insecure=on",
		"lookup_bind_dn=cn=admin,dc=min,dc=io",
		"lookup_bind_password=admin",
		"user_dn_search_base_dn=dc=min,dc=io",
		"user_dn_search_filter=(uid=%s)",
		"user_dn_attributes=sshPublicKey",
		"group_search_base_dn=ou=swengg,dc=min,dc=io",
		"group_search_filter=(&(objectclass=groupofnames)(member=%d))",
	}
	_, err := s.adm.SetConfigKV(ctx, strings.Join(configCmds, " "))
	if err != nil {
		c.Fatalf("unable to setup LDAP for tests: %v", err)
	}

	s.RestartIAMSuite(c)
}

// SetUpLDAPWithNonNormalizedBaseDN - expects to setup an LDAP test server using
// the test LDAP container and canned data from
// https://github.com/minio/minio-ldap-testing
//
// Sets up non-normalized base DN configuration for testing.
func (s *TestSuiteIAM) SetUpLDAPWithNonNormalizedBaseDN(c *check, serverAddr string) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	configCmds := []string{
		"identity_ldap",
		fmt.Sprintf("server_addr=%s", serverAddr),
		"server_insecure=on",
		"lookup_bind_dn=cn=admin,dc=min,dc=io",
		"lookup_bind_password=admin",
		// `DC` is intentionally capitalized here.
		"user_dn_search_base_dn=DC=min,DC=io",
		"user_dn_search_filter=(uid=%s)",
		// `DC` is intentionally capitalized here.
		"group_search_base_dn=ou=swengg,DC=min,dc=io",
		"group_search_filter=(&(objectclass=groupofnames)(member=%d))",
	}
	_, err := s.adm.SetConfigKV(ctx, strings.Join(configCmds, " "))
	if err != nil {
		c.Fatalf("unable to setup LDAP for tests: %v", err)
	}

	s.RestartIAMSuite(c)
}

const (
	EnvTestLDAPServer = "_MINIO_LDAP_TEST_SERVER"
)

func TestIAMWithLDAPServerSuite(t *testing.T) {
	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				ldapServer := os.Getenv(EnvTestLDAPServer)
				if ldapServer == "" {
					c.Skipf("Skipping LDAP test as no LDAP server is provided via %s", EnvTestLDAPServer)
				}

				suite.SetUpSuite(c)
				suite.SetUpLDAP(c, ldapServer)
				suite.TestLDAPSTS(c)
				suite.TestLDAPPolicyEntitiesLookup(c)
				suite.TestLDAPUnicodeVariations(c)
				suite.TestLDAPSTSServiceAccounts(c)
				suite.TestLDAPSTSServiceAccountsWithUsername(c)
				suite.TestLDAPSTSServiceAccountsWithGroups(c)
				suite.TestLDAPAttributesLookup(c)
				suite.TestLDAPCyrillicUser(c)
				suite.TestLDAPLongNonASCIIDN(c)
				suite.TestLDAPSlashDN(c)
				suite.TearDownSuite(c)
			},
		)
	}
}

type ldapSTSErrorResult struct {
	StatusCode int
	RetryAfter string
	Code       string
	Message    string
	Body       string
}

type ldapSTSHTTPResult struct {
	StatusCode int
	RetryAfter string
	Body       string
}

func withGlobalSTSLDAPLoginRateLimiterForTest(limiter *stsLDAPLoginRateLimiter, fn func()) {
	previous := globalSTSLDAPLoginRateLimiter
	globalSTSLDAPLoginRateLimiter = limiter
	defer func() {
		globalSTSLDAPLoginRateLimiter = previous
	}()

	fn()
}

func withLDAPSTSTrustedProxiesForTest(t *testing.T, trustedProxies string, fn func()) {
	t.Helper()

	previousIAMSys := globalIAMSys
	if globalIAMSys == nil {
		globalIAMSys = &IAMSys{}
	}
	previous := globalIAMSys.LDAPConfig.Clone()
	if err := globalIAMSys.LDAPConfig.SetSTSTrustedProxies(trustedProxies); err != nil {
		t.Fatalf("unable to set LDAP STS trusted proxies for test: %v", err)
	}
	defer func() {
		globalIAMSys.LDAPConfig = previous
		globalIAMSys = previousIAMSys
	}()

	fn()
}

func singleHeader(key, value string) http.Header {
	header := make(http.Header)
	if key != "" {
		header.Set(key, value)
	}
	return header
}

func (s *TestSuiteIAM) postLDAPSTSWithHeaders(c *check, username, password string, headers http.Header) ldapSTSHTTPResult {
	c.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	form := url.Values{}
	form.Set("Action", ldapIdentity)
	form.Set("Version", stsAPIVersion)
	form.Set(stsLDAPUsername, username)
	form.Set(stsLDAPPassword, password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endPoint, strings.NewReader(form.Encode()))
	if err != nil {
		c.Fatalf("unexpected request creation error: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := s.TestSuiteCommon.client.Do(req)
	if err != nil {
		c.Fatalf("unexpected LDAP STS request error: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.Fatalf("unexpected LDAP STS response read error: %v", err)
	}

	return ldapSTSHTTPResult{
		StatusCode: resp.StatusCode,
		RetryAfter: resp.Header.Get("Retry-After"),
		Body:       string(body),
	}
}

func (s *TestSuiteIAM) postLDAPSTS(c *check, username, password string) ldapSTSHTTPResult {
	c.Helper()
	return s.postLDAPSTSWithHeaders(c, username, password, nil)
}

func (s *TestSuiteIAM) postLDAPSTSForError(c *check, username, password string) ldapSTSErrorResult {
	c.Helper()

	result := s.postLDAPSTS(c, username, password)
	if result.StatusCode == http.StatusOK {
		c.Fatalf("expected LDAP STS request to fail, got success: %s", result.Body)
	}

	var stsErr STSErrorResponse
	if err := xml.Unmarshal([]byte(result.Body), &stsErr); err != nil {
		c.Fatalf("unexpected LDAP STS XML decode error: %v, body: %s", err, result.Body)
	}

	return ldapSTSErrorResult{
		StatusCode: result.StatusCode,
		RetryAfter: result.RetryAfter,
		Code:       stsErr.Error.Code,
		Message:    stsErr.Error.Message,
		Body:       result.Body,
	}
}

func (s *TestSuiteIAM) TestLDAPSTSAuthFailureUniformResponse(c *check) {
	withGlobalSTSLDAPLoginRateLimiterForTest(
		newSTSLDAPLoginRateLimiter(time.Minute, stsLDAPLoginBurst, stsLDAPLoginEntryTTL),
		func() {
			missingUser := s.postLDAPSTSForError(c, "missing-user", "nottherightpassword")
			wrongPassword := s.postLDAPSTSForError(c, "dillon", "nottherightpassword")

			if missingUser.StatusCode != http.StatusBadRequest {
				c.Fatalf("expected missing-user request status %d, got %d", http.StatusBadRequest, missingUser.StatusCode)
			}
			if wrongPassword.StatusCode != http.StatusBadRequest {
				c.Fatalf("expected wrong-password request status %d, got %d", http.StatusBadRequest, wrongPassword.StatusCode)
			}
			if missingUser.Code != "InvalidParameterValue" || wrongPassword.Code != "InvalidParameterValue" {
				c.Fatalf("expected InvalidParameterValue for both auth failures, got missing=%q wrong=%q", missingUser.Code, wrongPassword.Code)
			}
			if missingUser.Message != errLDAPAuthenticationFailed.Error() || wrongPassword.Message != errLDAPAuthenticationFailed.Error() {
				c.Fatalf("expected uniform LDAP auth failure message, got missing=%q wrong=%q", missingUser.Message, wrongPassword.Message)
			}
			if strings.Contains(strings.ToLower(missingUser.Body), "unable to find user dn") {
				c.Fatalf("missing-user response leaked lookup details: %s", missingUser.Body)
			}
			if strings.Contains(strings.ToLower(wrongPassword.Body), "ldap auth failed for dn") {
				c.Fatalf("wrong-password response leaked bind details: %s", wrongPassword.Body)
			}
		},
	)
}

func (s *TestSuiteIAM) TestLDAPSTSRateLimit(c *check) {
	withGlobalSTSLDAPLoginRateLimiterForTest(
		newSTSLDAPLoginRateLimiter(time.Hour, 2, stsLDAPLoginEntryTTL),
		func() {
			first := s.postLDAPSTSForError(c, "dillon", "nottherightpassword")
			second := s.postLDAPSTSForError(c, "dillon", "nottherightpassword")
			throttled := s.postLDAPSTSForError(c, "dillon", "nottherightpassword")

			if first.StatusCode != http.StatusBadRequest || second.StatusCode != http.StatusBadRequest {
				c.Fatalf("expected first two failed auth attempts to return %d, got %d and %d", http.StatusBadRequest, first.StatusCode, second.StatusCode)
			}
			if throttled.StatusCode != http.StatusTooManyRequests {
				c.Fatalf("expected throttled request status %d, got %d", http.StatusTooManyRequests, throttled.StatusCode)
			}
			if throttled.Code != "ThrottlingException" {
				c.Fatalf("expected throttled code %q, got %q", "ThrottlingException", throttled.Code)
			}
			if throttled.Message != "Request throttled, please retry later." {
				c.Fatalf("expected throttled message %q, got %q", "Request throttled, please retry later.", throttled.Message)
			}
			if throttled.RetryAfter != fmt.Sprintf("%d", stsLDAPLoginRetryAfterSec) {
				c.Fatalf("expected Retry-After %d, got %q", stsLDAPLoginRetryAfterSec, throttled.RetryAfter)
			}
		},
	)
}

func (s *TestSuiteIAM) TestLDAPSTSSuccessDoesNotConsumeRateLimit(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	userReq := madmin.PolicyAssociationReq{
		Policies: []string{"consoleAdmin"},
		User:     "uid=dillon,ou=people,ou=swengg,dc=min,dc=io",
	}
	if _, err := s.adm.AttachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("unable to attach LDAP policy for success rate-limit test: %v", err)
	}

	withGlobalSTSLDAPLoginRateLimiterForTest(
		newSTSLDAPLoginRateLimiter(time.Hour, 2, stsLDAPLoginEntryTTL),
		func() {
			for attempt := 1; attempt <= 3; attempt++ {
				success := s.postLDAPSTS(c, "dillon", "dillon")
				if success.StatusCode != http.StatusOK {
					c.Fatalf("expected successful LDAP STS login on attempt %d, got status %d body: %s", attempt, success.StatusCode, success.Body)
				}
			}

			firstFailure := s.postLDAPSTSForError(c, "dillon", "nottherightpassword")
			secondFailure := s.postLDAPSTSForError(c, "dillon", "nottherightpassword")
			throttled := s.postLDAPSTSForError(c, "dillon", "nottherightpassword")

			if firstFailure.StatusCode != http.StatusBadRequest || secondFailure.StatusCode != http.StatusBadRequest {
				c.Fatalf("expected failed auth attempts after successful logins to return %d, got %d and %d", http.StatusBadRequest, firstFailure.StatusCode, secondFailure.StatusCode)
			}
			if throttled.StatusCode != http.StatusTooManyRequests {
				c.Fatalf("expected third failed auth attempt after successful logins to be throttled with %d, got %d", http.StatusTooManyRequests, throttled.StatusCode)
			}
		},
	)
}

func (s *TestSuiteIAM) TestLDAPSTSUpstreamFailure(c *check) {
	original := globalIAMSys.LDAPConfig.Clone()
	globalIAMSys.LDAPConfig.LDAP.ServerAddr = "127.0.0.1:1"
	defer func() {
		globalIAMSys.LDAPConfig = original
	}()

	withGlobalSTSLDAPLoginRateLimiterForTest(
		newSTSLDAPLoginRateLimiter(time.Hour, 2, stsLDAPLoginEntryTTL),
		func() {
			for range 3 {
				upstreamFailure := s.postLDAPSTSForError(c, "dillon", "dillon")

				if upstreamFailure.StatusCode != http.StatusInternalServerError {
					c.Fatalf("expected upstream failure status %d, got %d", http.StatusInternalServerError, upstreamFailure.StatusCode)
				}
				if upstreamFailure.Code != "InternalError" {
					c.Fatalf("expected upstream failure code %q, got %q", "InternalError", upstreamFailure.Code)
				}
				if upstreamFailure.Message != stsErrCodes.ToSTSErr(ErrSTSUpstreamError).Description {
					c.Fatalf("expected upstream failure message %q, got %q", stsErrCodes.ToSTSErr(ErrSTSUpstreamError).Description, upstreamFailure.Message)
				}
				if upstreamFailure.Message == errLDAPAuthenticationFailed.Error() {
					c.Fatalf("expected upstream failure to stay distinct from auth failure, got %q", upstreamFailure.Message)
				}
			}

			globalIAMSys.LDAPConfig = original

			authFailure := s.postLDAPSTSForError(c, "dillon", "nottherightpassword")
			if authFailure.StatusCode == http.StatusTooManyRequests {
				c.Fatalf("expected upstream failures not to consume rate limit budget, got throttled response: %+v", authFailure)
			}
			if authFailure.StatusCode != http.StatusBadRequest {
				c.Fatalf("expected auth failure after upstream recovery to return %d, got %d", http.StatusBadRequest, authFailure.StatusCode)
			}
		},
	)
}

func (s *TestSuiteIAM) TestLDAPSTSTrustedProxyRateLimit(c *check) {
	withLDAPSTSTrustedProxiesForTest(c.T, "127.0.0.0/8,::1/128", func() {
		withGlobalSTSLDAPLoginRateLimiterForTest(
			newSTSLDAPLoginRateLimiter(time.Hour, 1, stsLDAPLoginEntryTTL),
			func() {
				// These usernames intentionally do not exist. The test asserts that
				// LDAP user-not-found stays classified as an auth error, so failed
				// attempts still commit the reservation and hit the source bucket.
				first := s.postLDAPSTSWithHeaders(c, "missing-user-a", "nottherightpassword", singleHeader("X-Real-IP", "203.0.113.10"))
				second := s.postLDAPSTSWithHeaders(c, "missing-user-b", "nottherightpassword", singleHeader("X-Real-IP", "198.51.100.23"))
				third := s.postLDAPSTSWithHeaders(c, "missing-user-c", "nottherightpassword", singleHeader("X-Real-IP", "203.0.113.10"))

				if first.StatusCode != http.StatusBadRequest {
					c.Fatalf("expected first trusted-proxy LDAP STS auth failure to return %d, got %d body: %s", http.StatusBadRequest, first.StatusCode, first.Body)
				}
				if second.StatusCode != http.StatusBadRequest {
					c.Fatalf("expected a different forwarded client IP behind the same trusted proxy to avoid source throttling, got %d body: %s", second.StatusCode, second.Body)
				}
				if third.StatusCode != http.StatusTooManyRequests {
					c.Fatalf("expected the same forwarded client IP behind the trusted proxy to be throttled with %d, got %d body: %s", http.StatusTooManyRequests, third.StatusCode, third.Body)
				}
			},
		)
	})
}

func TestIAMWithLDAPSecurityServerSuite(t *testing.T) {
	tests := []struct {
		name string
		run  func(*TestSuiteIAM, *check, string)
	}{
		{
			name: "AuthFailureUniformResponse",
			run: func(suite *TestSuiteIAM, c *check, ldapServer string) {
				suite.TestLDAPSTSAuthFailureUniformResponse(c)
			},
		},
		{
			name: "RateLimit",
			run: func(suite *TestSuiteIAM, c *check, ldapServer string) {
				suite.TestLDAPSTSRateLimit(c)
			},
		},
		{
			name: "SuccessDoesNotConsumeRateLimit",
			run: func(suite *TestSuiteIAM, c *check, ldapServer string) {
				suite.TestLDAPSTSSuccessDoesNotConsumeRateLimit(c)
			},
		},
		{
			name: "UpstreamFailure",
			run: func(suite *TestSuiteIAM, c *check, ldapServer string) {
				suite.TestLDAPSTSUpstreamFailure(c)
			},
		},
		{
			name: "TrustedProxyRateLimit",
			run: func(suite *TestSuiteIAM, c *check, ldapServer string) {
				suite.TestLDAPSTSTrustedProxyRateLimit(c)
			},
		},
	}

	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				ldapServer := os.Getenv(EnvTestLDAPServer)
				if ldapServer == "" {
					t.Skipf("Skipping LDAP security test as no LDAP server is provided via %s", EnvTestLDAPServer)
				}

				suite := testCase
				for _, tc := range tests {
					tc := tc
					t.Run(tc.name, func(t *testing.T) {
						c := &check{t, testCase.serverType}
						suite.SetUpSuite(c)
						suite.SetUpLDAP(c, ldapServer)
						tc.run(suite, c, ldapServer)
						suite.TearDownSuite(c)
					})
				}
			},
		)
	}
}

// This test is for a fix added to handle non-normalized base DN values in the
// LDAP configuration. It runs the existing LDAP sub-tests with a non-normalized
// LDAP configuration.
func TestIAMWithLDAPNonNormalizedBaseDNConfigServerSuite(t *testing.T) {
	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				ldapServer := os.Getenv(EnvTestLDAPServer)
				if ldapServer == "" {
					c.Skipf("Skipping LDAP test as no LDAP server is provided via %s", EnvTestLDAPServer)
				}

				suite.SetUpSuite(c)
				suite.SetUpLDAPWithNonNormalizedBaseDN(c, ldapServer)
				suite.TestLDAPSTS(c)
				suite.TestLDAPPolicyEntitiesLookup(c)
				suite.TestLDAPUnicodeVariations(c)
				suite.TestLDAPSTSServiceAccounts(c)
				suite.TestLDAPSTSServiceAccountsWithUsername(c)
				suite.TestLDAPSTSServiceAccountsWithGroups(c)
				suite.TestLDAPSlashDN(c)
				suite.TearDownSuite(c)
			},
		)
	}
}

func TestIAMExportImportWithLDAP(t *testing.T) {
	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				ldapServer := os.Getenv(EnvTestLDAPServer)
				if ldapServer == "" {
					c.Skipf("Skipping LDAP test as no LDAP server is provided via %s", EnvTestLDAPServer)
				}

				iamTestContentCases := []iamTestContent{
					{
						policies: map[string][]byte{
							"mypolicy": []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket","s3:PutObject"],"Resource":["arn:aws:s3:::mybucket/*"]}]}`),
						},
						ldapUserPolicyMappings: map[string][]string{
							"uid=dillon,ou=people,ou=swengg,dc=min,dc=io": {"mypolicy"},
							"uid=liza,ou=people,ou=swengg,dc=min,dc=io":   {"consoleAdmin"},
						},
						ldapGroupPolicyMappings: map[string][]string{
							"cn=projectb,ou=groups,ou=swengg,dc=min,dc=io": {"mypolicy"},
							"cn=projecta,ou=groups,ou=swengg,dc=min,dc=io": {"consoleAdmin"},
						},
					},
				}

				for caseNum, content := range iamTestContentCases {
					suite.SetUpSuite(c)
					suite.SetUpLDAP(c, ldapServer)
					exportedContent := suite.TestIAMExport(c, caseNum, content)
					suite.TearDownSuite(c)
					suite.SetUpSuite(c)
					suite.SetUpLDAP(c, ldapServer)
					suite.TestIAMImport(c, exportedContent, caseNum, content)
					suite.TearDownSuite(c)
				}
			},
		)
	}
}

type matchingAuthError struct{}

func (matchingAuthError) Error() string {
	return "ldap auth failed"
}

func (matchingAuthError) Is(target error) bool {
	return targetIsLDAPAuthFailure(target)
}

func targetIsLDAPAuthFailure(target error) bool {
	return target != nil && target.Error() == "ldap authentication failed"
}

func TestSTSLDAPLoginRateLimiter(t *testing.T) {
	limiter := newSTSLDAPLoginRateLimiter(time.Hour, 2, time.Minute)

	if !limiter.Allow("192.0.2.10") {
		t.Fatal("expected first attempt to be allowed")
	}
	if !limiter.Allow("192.0.2.10") {
		t.Fatal("expected second attempt within burst to be allowed")
	}
	if limiter.Allow("192.0.2.10") {
		t.Fatal("expected source IP bucket to be throttled after burst")
	}

	// A different source IP has its own independent bucket, so one client
	// cannot exhaust another's budget (no per-username lockout dimension).
	if !limiter.Allow("192.0.2.11") {
		t.Fatal("expected a different source IP to be allowed")
	}

	// An empty source IP cannot be identified and must never be throttled,
	// otherwise all such requests would collapse into one shared bucket.
	if !limiter.Allow("") || !limiter.Allow("") {
		t.Fatal("expected unidentified source to stay unthrottled")
	}
}

func TestSTSLDAPLoginRateLimiterReserveCancel(t *testing.T) {
	limiter := newSTSLDAPLoginRateLimiter(time.Hour, 1, time.Minute)

	reservation := limiter.Reserve("192.0.2.10")
	if reservation == nil {
		t.Fatal("expected first reservation to succeed")
	}
	if limiter.Reserve("192.0.2.10") != nil {
		t.Fatal("expected second reservation on the same source IP to be throttled before cancel")
	}

	reservation.Cancel()

	reservation = limiter.Reserve("192.0.2.10")
	if reservation == nil {
		t.Fatal("expected canceled reservation to restore source-IP capacity")
	}
	reservation.Cancel()

	reservation = limiter.Reserve("192.0.2.11")
	if reservation == nil {
		t.Fatal("expected a different source IP to have independent capacity")
	}
	reservation.Cancel()
}

func TestSTSLDAPLoginKeyLimiterCancelDoesNotOverCreditAfterRefill(t *testing.T) {
	set := newSTSLDAPLoginKeyLimiterSet(10*time.Millisecond, 2, time.Minute)
	start := time.Unix(0, 0)

	first := set.Reserve(start, "192.0.2.10")
	if first == nil {
		t.Fatal("expected first reservation to succeed")
	}
	second := set.Reserve(start.Add(5*time.Millisecond), "192.0.2.10")
	if second == nil {
		t.Fatal("expected second reservation to succeed while one token remains available")
	}

	first.CancelAt(start.Add(10 * time.Millisecond))

	third := set.Reserve(start.Add(10*time.Millisecond), "192.0.2.10")
	if third == nil {
		t.Fatal("expected canceled reservation to restore exactly one slot")
	}
	defer third.CancelAt(start.Add(10 * time.Millisecond))

	if extra := set.Reserve(start.Add(10*time.Millisecond), "192.0.2.10"); extra != nil {
		extra.CancelAt(start.Add(10 * time.Millisecond))
		t.Fatal("expected only one slot to be restored after cancel; got over-credit from refill")
	}

	second.CancelAt(start.Add(10 * time.Millisecond))
}

func TestSTSLDAPLoginRateLimiterConcurrentReserveLifecycle(t *testing.T) {
	limiter := newSTSLDAPLoginRateLimiter(time.Hour, 4, time.Minute)

	const workers = 8
	start := make(chan struct{})
	finish := make(chan struct{})
	var wg sync.WaitGroup
	var reserveWG sync.WaitGroup
	reservations := make([]*stsLDAPLoginReservation, workers)
	var canceledReservations atomic.Int32

	reserveWG.Add(workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			<-start

			reservations[worker] = limiter.Reserve("192.0.2.10")
			reserveWG.Done()
			if reservations[worker] == nil {
				return
			}

			<-finish
			if worker%2 == 0 {
				canceledReservations.Add(1)
				reservations[worker].Cancel()
				return
			}

			reservations[worker].Commit()
		}(i)
	}

	close(start)
	reserveWG.Wait()

	successfulReservations := 0
	for _, reservation := range reservations {
		if reservation != nil {
			successfulReservations++
		}
	}
	if got := successfulReservations; got != 4 {
		t.Fatalf("expected exactly 4 successful concurrent reservations, got %d", got)
	}

	close(finish)
	wg.Wait()

	remainingBudget := 0
	for {
		reservation := limiter.Reserve("192.0.2.10")
		if reservation == nil {
			break
		}
		remainingBudget++
		reservation.Commit()
	}

	if want, got := int(canceledReservations.Load()), remainingBudget; got != want {
		t.Fatalf("expected %d tokens to remain after concurrent commit/cancel mix, got %d", want, got)
	}
}

func TestGetSTSLDAPLoginSourceIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{name: "empty", remoteAddr: "", want: ""},
		{name: "ipv4", remoteAddr: "192.0.2.10:9000", want: "192.0.2.10"},
		{name: "ipv6", remoteAddr: "[2001:db8::10]:9000", want: "2001:db8::10"},
		{name: "bare-host", remoteAddr: "192.0.2.10", want: "192.0.2.10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{RemoteAddr: tt.remoteAddr}
			if got := getSTSLDAPLoginSourceIP(req); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestGetSTSLDAPLoginSourceIPIgnoresSpoofedForwardingHeaders(t *testing.T) {
	tests := []struct {
		name        string
		headerKey   string
		headerValue string
	}{
		{
			name:        "x-forwarded-for",
			headerKey:   "X-Forwarded-For",
			headerValue: "203.0.113.10, 198.51.100.24",
		},
		{
			name:        "x-real-ip",
			headerKey:   "X-Real-IP",
			headerValue: "203.0.113.10",
		},
		{
			name:        "forwarded",
			headerKey:   "Forwarded",
			headerValue: `for=203.0.113.10;proto=https`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header:     singleHeader(tt.headerKey, tt.headerValue),
				RemoteAddr: "192.0.2.10:9000",
			}

			if got := getSTSLDAPLoginSourceIP(req); got != "192.0.2.10" {
				t.Fatalf("expected helper to ignore spoofed %s and return peer address, got %q", tt.headerKey, got)
			}
		})
	}
}

func TestGetSTSLDAPLoginSourceIPUsesForwardedHeadersForTrustedProxy(t *testing.T) {
	tests := []struct {
		name        string
		headerKey   string
		headerValue string
		want        string
	}{
		{
			name:        "x-forwarded-for",
			headerKey:   "X-Forwarded-For",
			headerValue: "203.0.113.10",
			want:        "203.0.113.10",
		},
		{
			name:        "x-real-ip",
			headerKey:   "X-Real-IP",
			headerValue: "203.0.113.10",
			want:        "203.0.113.10",
		},
	}

	withLDAPSTSTrustedProxiesForTest(t, "192.0.2.0/24", func() {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := &http.Request{
					Header:     singleHeader(tt.headerKey, tt.headerValue),
					RemoteAddr: "192.0.2.10:9000",
				}

				if got := getSTSLDAPLoginSourceIP(req); got != tt.want {
					t.Fatalf("expected trusted proxy header %s to resolve %q, got %q", tt.headerKey, tt.want, got)
				}
			})
		}
	})
}

// A client behind a trusted, appending proxy can prepend a spoofed left-most
// X-Forwarded-For value. The right-to-left walk must skip only trusted hops and
// return the real (right-most untrusted) client, ignoring the spoofed value.
func TestGetSTSLDAPLoginSourceIPTrustedProxyStripsSpoofedForwardedFor(t *testing.T) {
	withLDAPSTSTrustedProxiesForTest(t, "192.0.2.0/24", func() {
		req := &http.Request{
			Header:     singleHeader("X-Forwarded-For", "1.2.3.4, 198.51.100.50"),
			RemoteAddr: "192.0.2.10:9000",
		}
		if got := getSTSLDAPLoginSourceIP(req); got != "198.51.100.50" {
			t.Fatalf("expected spoofed left-most XFF entry to be ignored and real client returned, got %q", got)
		}
	})
}

// When several hops in the chain are trusted proxies, the walk skips all of
// them and resolves the left-most (real client) address.
func TestGetSTSLDAPLoginSourceIPTrustedProxyWalksMultipleTrustedHops(t *testing.T) {
	withLDAPSTSTrustedProxiesForTest(t, "192.0.2.0/24", func() {
		req := &http.Request{
			Header:     singleHeader("X-Forwarded-For", "203.0.113.10, 192.0.2.20, 192.0.2.21"),
			RemoteAddr: "192.0.2.10:9000",
		}
		if got := getSTSLDAPLoginSourceIP(req); got != "203.0.113.10" {
			t.Fatalf("expected walk to skip trusted hops and return real client, got %q", got)
		}
	})
}

// The RFC 7239 Forwarded header is not honored for trusted-proxy bucketing; such
// requests fall back to the safe peer-address bucket.
func TestGetSTSLDAPLoginSourceIPTrustedProxyIgnoresForwardedHeader(t *testing.T) {
	withLDAPSTSTrustedProxiesForTest(t, "192.0.2.0/24", func() {
		req := &http.Request{
			Header:     singleHeader("Forwarded", `for=203.0.113.10;proto=https`),
			RemoteAddr: "192.0.2.10:9000",
		}
		if got := getSTSLDAPLoginSourceIP(req); got != "192.0.2.10" {
			t.Fatalf("expected RFC 7239 Forwarded to be ignored and peer address used, got %q", got)
		}
	})
}

func TestGetSTSLDAPLoginSourceIPTrustedProxyPrefersXRealIPOverXForwardedFor(t *testing.T) {
	withLDAPSTSTrustedProxiesForTest(t, "192.0.2.0/24", func() {
		req := &http.Request{
			Header:     make(http.Header),
			RemoteAddr: "192.0.2.10:9000",
		}
		req.Header.Set("X-Forwarded-For", "198.51.100.99, 203.0.113.10")
		req.Header.Set("X-Real-IP", "203.0.113.10")

		if got := getSTSLDAPLoginSourceIP(req); got != "203.0.113.10" {
			t.Fatalf("expected trusted proxy path to prefer X-Real-IP over appended X-Forwarded-For, got %q", got)
		}
	})
}

// X-Real-IP is trusted verbatim (it cannot be chain-validated like X-Forwarded-For),
// so a client-supplied X-Real-IP that the proxy fails to overwrite wins even over a
// correctly appended X-Forwarded-For chain. This locks the documented deployment
// contract: the trusted proxy MUST overwrite X-Real-IP, otherwise it is a spoofing
// vector. If this assertion ever changes, the change must be deliberate.
func TestGetSTSLDAPLoginSourceIPTrustedProxyTrustsXRealIPVerbatim(t *testing.T) {
	withLDAPSTSTrustedProxiesForTest(t, "192.0.2.0/24", func() {
		req := &http.Request{
			Header:     make(http.Header),
			RemoteAddr: "192.0.2.10:9000",
		}
		// Attacker spoofs X-Real-IP with a value that appears nowhere in the XFF
		// chain; the trusted proxy still appends the real client (198.51.100.50).
		// The spoofed X-Real-IP wins, so the result can only have come from it.
		req.Header.Set("X-Real-IP", "10.10.10.10")
		req.Header.Set("X-Forwarded-For", "1.1.1.1, 198.51.100.50")

		if got := getSTSLDAPLoginSourceIP(req); got != "10.10.10.10" {
			t.Fatalf("expected verbatim X-Real-IP trust (spoofable contract), got %q", got)
		}
	})
}

func TestGetSTSLDAPLoginSourceIPTrustedProxyFallsBackToPeerWithoutForwardingHeaders(t *testing.T) {
	withLDAPSTSTrustedProxiesForTest(t, "192.0.2.0/24", func() {
		req := &http.Request{RemoteAddr: "192.0.2.10:9000"}
		if got := getSTSLDAPLoginSourceIP(req); got != "192.0.2.10" {
			t.Fatalf("expected trusted proxy path without forwarding headers to fall back to peer address, got %q", got)
		}
	})
}

func TestReserveSTSLDAPLoginUsesPeerAddressBuckets(t *testing.T) {
	tests := []struct {
		name        string
		headerKey   string
		firstValue  string
		secondValue string
	}{
		{
			name:        "x-forwarded-for",
			headerKey:   "X-Forwarded-For",
			firstValue:  "203.0.113.10",
			secondValue: "198.51.100.23, 198.51.100.24",
		},
		{
			name:        "x-real-ip",
			headerKey:   "X-Real-IP",
			firstValue:  "203.0.113.10",
			secondValue: "198.51.100.23",
		},
		{
			name:        "forwarded",
			headerKey:   "Forwarded",
			firstValue:  `for=203.0.113.10;proto=https`,
			secondValue: `for=198.51.100.23;proto=https`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"-same-peer", func(t *testing.T) {
			limiter := newSTSLDAPLoginRateLimiter(time.Hour, 2, time.Minute)
			withGlobalSTSLDAPLoginRateLimiterForTest(limiter, func() {
				req1 := &http.Request{
					Header:     singleHeader(tt.headerKey, tt.firstValue),
					RemoteAddr: "192.0.2.10:9000",
					Form:       url.Values{stsLDAPUsername: []string{"alice"}},
				}
				req2 := &http.Request{
					Header:     singleHeader(tt.headerKey, tt.secondValue),
					RemoteAddr: "192.0.2.10:9001",
					Form:       url.Values{stsLDAPUsername: []string{"bob"}},
				}

				reservation1 := reserveSTSLDAPLogin(req1)
				if reservation1 == nil {
					t.Fatal("expected first reservation to succeed")
				}
				defer reservation1.Cancel()

				reservation2 := reserveSTSLDAPLogin(req2)
				if reservation2 == nil {
					t.Fatal("expected second reservation to succeed with shared source bucket capacity")
				}
				defer reservation2.Cancel()

				if got := len(limiter.source.entries); got != 1 {
					t.Fatalf("expected requests from the same peer address to share one source bucket, got %d", got)
				}
				if _, ok := limiter.source.entries["192.0.2.10"]; !ok {
					t.Fatalf("expected source bucket for peer address %q, got keys %v", "192.0.2.10", limiter.source.entries)
				}
			})
		})

		t.Run(tt.name+"-different-peers", func(t *testing.T) {
			limiter := newSTSLDAPLoginRateLimiter(time.Hour, 1, time.Minute)
			withGlobalSTSLDAPLoginRateLimiterForTest(limiter, func() {
				req1 := &http.Request{
					Header:     singleHeader(tt.headerKey, tt.firstValue),
					RemoteAddr: "192.0.2.10:9000",
					Form:       url.Values{stsLDAPUsername: []string{"alice"}},
				}
				req2 := &http.Request{
					Header:     singleHeader(tt.headerKey, tt.firstValue),
					RemoteAddr: "192.0.2.11:9000",
					Form:       url.Values{stsLDAPUsername: []string{"bob"}},
				}

				reservation1 := reserveSTSLDAPLogin(req1)
				if reservation1 == nil {
					t.Fatal("expected first reservation to succeed")
				}
				defer reservation1.Cancel()

				reservation2 := reserveSTSLDAPLogin(req2)
				if reservation2 == nil {
					t.Fatal("expected second reservation from a different peer address to succeed")
				}
				defer reservation2.Cancel()

				if got := len(limiter.source.entries); got != 2 {
					t.Fatalf("expected requests from different peer addresses to use different source buckets, got %d", got)
				}
				if _, ok := limiter.source.entries["192.0.2.10"]; !ok {
					t.Fatalf("expected source bucket for peer address %q, got keys %v", "192.0.2.10", limiter.source.entries)
				}
				if _, ok := limiter.source.entries["192.0.2.11"]; !ok {
					t.Fatalf("expected source bucket for peer address %q, got keys %v", "192.0.2.11", limiter.source.entries)
				}
			})
		})
	}
}

func TestReserveSTSLDAPLoginUsesForwardedBucketsForTrustedProxy(t *testing.T) {
	limiter := newSTSLDAPLoginRateLimiter(time.Hour, 1, time.Minute)
	withGlobalSTSLDAPLoginRateLimiterForTest(limiter, func() {
		withLDAPSTSTrustedProxiesForTest(t, "192.0.2.0/24", func() {
			req1 := &http.Request{
				Header:     singleHeader("X-Forwarded-For", "203.0.113.10"),
				RemoteAddr: "192.0.2.10:9000",
				Form:       url.Values{stsLDAPUsername: []string{"alice"}},
			}
			req2 := &http.Request{
				Header:     singleHeader("X-Forwarded-For", "198.51.100.23"),
				RemoteAddr: "192.0.2.10:9001",
				Form:       url.Values{stsLDAPUsername: []string{"bob"}},
			}

			reservation1 := reserveSTSLDAPLogin(req1)
			if reservation1 == nil {
				t.Fatal("expected first reservation through trusted proxy to succeed")
			}
			defer reservation1.Cancel()

			reservation2 := reserveSTSLDAPLogin(req2)
			if reservation2 == nil {
				t.Fatal("expected forwarded client IPs behind the same trusted proxy to use distinct source buckets")
			}
			defer reservation2.Cancel()

			if got := len(limiter.source.entries); got != 2 {
				t.Fatalf("expected distinct forwarded client IPs to use two source buckets, got %d", got)
			}
			if _, ok := limiter.source.entries["203.0.113.10"]; !ok {
				t.Fatalf("expected source bucket for forwarded client IP %q, got keys %v", "203.0.113.10", limiter.source.entries)
			}
			if _, ok := limiter.source.entries["198.51.100.23"]; !ok {
				t.Fatalf("expected source bucket for forwarded client IP %q, got keys %v", "198.51.100.23", limiter.source.entries)
			}
		})
	})
}

func TestLDAPBindErrorToSTS(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		code    STSErrorCode
		message string
	}{
		{
			name:    "auth failure",
			err:     matchingAuthError{},
			code:    ErrSTSInvalidParameterValue,
			message: errLDAPAuthenticationFailed.Error(),
		},
		{
			name:    "upstream failure",
			err:     errors.New("ldap server unavailable"),
			code:    ErrSTSUpstreamError,
			message: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := ldapBindErrorToSTS(tt.err)
			if code != tt.code {
				t.Fatalf("expected code %v, got %v", tt.code, code)
			}
			if tt.message == "" {
				if err != nil {
					t.Fatalf("expected nil response error, got %v", err)
				}
				return
			}
			if err == nil || err.Error() != tt.message {
				t.Fatalf("expected %q, got %v", tt.message, err)
			}
		})
	}
}

func TestSTSLDAPLoginRateLimiterCleanup(t *testing.T) {
	set := newSTSLDAPLoginKeyLimiterSet(time.Hour, 1, time.Minute)
	start := time.Unix(0, 0)

	if !set.Allow(start, "old-key") {
		t.Fatal("expected initial key to be allowed")
	}
	if len(set.entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(set.entries))
	}

	if !set.Allow(start.Add(2*time.Minute), "new-key") {
		t.Fatal("expected new key to be allowed after ttl expiry")
	}
	if _, ok := set.entries["old-key"]; ok {
		t.Fatal("expected expired key to be cleaned up")
	}
}

func TestWriteSTSThrottledResponse(t *testing.T) {
	rr := httptest.NewRecorder()

	writeSTSThrottledResponse(rr)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected status %d, got %d", http.StatusTooManyRequests, rr.Code)
	}
	if got := rr.Header().Get("Retry-After"); got != "6" {
		t.Fatalf("expected Retry-After header %q, got %q", "6", got)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "<Code>ThrottlingException</Code>") {
		t.Fatalf("expected throttling code in response, got %s", body)
	}
	if !strings.Contains(body, "<Message>Request throttled, please retry later.</Message>") {
		t.Fatalf("expected throttling message in response, got %s", body)
	}
}

func TestIAMImportAssetWithLDAP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), testDefaultTimeout)
	defer cancel()

	exportContentStrings := map[string]string{
		allPoliciesFile: `{"consoleAdmin":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:*"]},{"Effect":"Allow","Action":["kms:*"]},{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]}]},"diagnostics":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:Prometheus","admin:Profiling","admin:ServerTrace","admin:ConsoleLog","admin:ServerInfo","admin:TopLocksInfo","admin:OBDInfo","admin:BandwidthMonitor"],"Resource":["arn:aws:s3:::*"]}]},"readonly":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetBucketLocation","s3:GetObject"],"Resource":["arn:aws:s3:::*"]}]},"readwrite":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]}]},"writeonly":{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::*"]}]}}`,

		// Built-in user should be imported without errors even if LDAP is
		// enabled.
		allUsersFile: `{
  "foo": {
    "secretKey": "foobar123",
    "status": "enabled"
  }
}
`,
		// Built-in groups should be imported without errors even if LDAP is
		// enabled.
		allGroupsFile: `{
  "mygroup": {
    "version": 1,
    "status": "enabled",
    "members": [
      "foo"
    ],
    "updatedAt": "2024-04-23T21:34:43.587429659Z"
  }
}
`,
		// The `cn=projecty,..` group below is not under a configured DN, but we
		// should still import without an error.
		allSvcAcctsFile: `{
    "u4ccRswj62HV3Ifwima7": {
        "parent": "uid=svc.algorithm,OU=swengg,DC=min,DC=io",
        "accessKey": "u4ccRswj62HV3Ifwima7",
        "secretKey": "ZoEoZdLlzVbOlT9rbhD7ZN7TLyiYXSAlB79uGEge",
        "groups": ["cn=project.c,ou=groups,OU=swengg,DC=min,DC=io", "cn=projecty,ou=groups,ou=hwengg,dc=min,dc=io"],
        "claims": {
            "accessKey": "u4ccRswj62HV3Ifwima7",
            "ldapUser": "uid=svc.algorithm,ou=swengg,dc=min,dc=io",
            "ldapUsername": "svc.algorithm",
            "parent": "uid=svc.algorithm,ou=swengg,dc=min,dc=io",
            "sa-policy": "inherited-policy"
        },
        "sessionPolicy": null,
        "status": "on",
        "name": "",
        "description": ""
    }
}
`,
		// Built-in user-to-policies mapping should be imported without errors
		// even if LDAP is enabled.
		userPolicyMappingsFile: `{
  "foo": {
    "version": 0,
    "policy": "readwrite",
    "updatedAt": "2024-04-23T21:34:43.815519816Z"
  }
}
`,
		// Contains:
		//
		// 1. duplicate mapping with same policy, we should not error out;
		//
		// 2. non-LDAP group mapping, we should not error out;
		groupPolicyMappingsFile: `{
    "cn=project.c,ou=groups,ou=swengg,DC=min,dc=io": {
        "version": 0,
        "policy": "consoleAdmin",
        "updatedAt": "2024-04-17T23:54:28.442998301Z"
    },
    "mygroup": {
        "version": 0,
        "policy": "consoleAdmin",
        "updatedAt": "2024-04-23T21:34:43.66922872Z"
    },
    "cn=project.c,ou=groups,OU=swengg,DC=min,DC=io": {
        "version": 0,
        "policy": "consoleAdmin",
        "updatedAt": "2024-04-17T20:54:28.442998301Z"
    }
}
`,
		stsUserPolicyMappingsFile: `{
    "uid=dillon,ou=people,OU=swengg,DC=min,DC=io": {
        "version": 0,
        "policy": "consoleAdmin",
        "updatedAt": "2024-04-17T23:54:10.606645642Z"
    }
}
`,
	}
	exportContent := map[string][]byte{}
	for k, v := range exportContentStrings {
		exportContent[k] = []byte(v)
	}

	var importContent []byte
	{
		var b bytes.Buffer
		zipWriter := zip.NewWriter(&b)
		rawDataFn := func(r io.Reader, filename string, sz int) error {
			header, zerr := zip.FileInfoHeader(dummyFileInfo{
				name:    filename,
				size:    int64(sz),
				mode:    0o600,
				modTime: time.Now(),
				isDir:   false,
				sys:     nil,
			})
			if zerr != nil {
				adminLogIf(ctx, zerr)
				return nil
			}
			header.Method = zip.Deflate
			zwriter, zerr := zipWriter.CreateHeader(header)
			if zerr != nil {
				adminLogIf(ctx, zerr)
				return nil
			}
			if _, err := io.Copy(zwriter, r); err != nil {
				adminLogIf(ctx, err)
			}
			return nil
		}
		for _, f := range iamExportFiles {
			iamFile := pathJoin(iamAssetsDir, f)

			fileContent, ok := exportContent[f]
			if !ok {
				t.Fatalf("missing content for %s", f)
			}

			if err := rawDataFn(bytes.NewReader(fileContent), iamFile, len(fileContent)); err != nil {
				t.Fatalf("failed to write %s: %v", iamFile, err)
			}
		}
		zipWriter.Close()
		importContent = b.Bytes()
	}

	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				ldapServer := os.Getenv(EnvTestLDAPServer)
				if ldapServer == "" {
					c.Skipf("Skipping LDAP test as no LDAP server is provided via %s", EnvTestLDAPServer)
				}

				suite.SetUpSuite(c)
				suite.SetUpLDAP(c, ldapServer)
				suite.TestIAMImportAssetContent(c, importContent)
				suite.TearDownSuite(c)
			},
		)
	}
}

type iamTestContent struct {
	policies                map[string][]byte
	ldapUserPolicyMappings  map[string][]string
	ldapGroupPolicyMappings map[string][]string
}

func (s *TestSuiteIAM) TestIAMExport(c *check, caseNum int, content iamTestContent) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	for policy, policyBytes := range content.policies {
		err := s.adm.AddCannedPolicy(ctx, policy, policyBytes)
		if err != nil {
			c.Fatalf("export %d: policy add error: %v", caseNum, err)
		}
	}

	for userDN, policies := range content.ldapUserPolicyMappings {
		// No need to detach, we are starting from a clean slate after exporting.
		_, err := s.adm.AttachPolicyLDAP(ctx, madmin.PolicyAssociationReq{
			Policies: policies,
			User:     userDN,
		})
		if err != nil {
			c.Fatalf("export %d: Unable to attach policy: %v", caseNum, err)
		}
	}

	for groupDN, policies := range content.ldapGroupPolicyMappings {
		_, err := s.adm.AttachPolicyLDAP(ctx, madmin.PolicyAssociationReq{
			Policies: policies,
			Group:    groupDN,
		})
		if err != nil {
			c.Fatalf("export %d: Unable to attach group policy: %v", caseNum, err)
		}
	}

	contentReader, err := s.adm.ExportIAM(ctx)
	if err != nil {
		c.Fatalf("export %d: Unable to export IAM: %v", caseNum, err)
	}
	defer contentReader.Close()

	expContent, err := io.ReadAll(contentReader)
	if err != nil {
		c.Fatalf("export %d: Unable to read exported content: %v", caseNum, err)
	}

	return expContent
}

type dummyCloser struct {
	io.Reader
}

func (d dummyCloser) Close() error { return nil }

func (s *TestSuiteIAM) TestIAMImportAssetContent(c *check, content []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	dummyCloser := dummyCloser{bytes.NewReader(content)}
	err := s.adm.ImportIAM(ctx, dummyCloser)
	if err != nil {
		c.Fatalf("Unable to import IAM: %v", err)
	}

	entRes, err := s.adm.GetLDAPPolicyEntities(ctx, madmin.PolicyEntitiesQuery{})
	if err != nil {
		c.Fatalf("Unable to get policy entities: %v", err)
	}

	expected := madmin.PolicyEntitiesResult{
		PolicyMappings: []madmin.PolicyEntities{
			{
				Policy: "consoleAdmin",
				Users:  []string{"uid=dillon,ou=people,ou=swengg,dc=min,dc=io"},
				Groups: []string{"cn=project.c,ou=groups,ou=swengg,dc=min,dc=io"},
			},
		},
	}

	entRes.Timestamp = time.Time{}
	if !reflect.DeepEqual(expected, entRes) {
		c.Fatalf("policy entities mismatch: expected: %v, got: %v", expected, entRes)
	}

	dn := "uid=svc.algorithm,ou=swengg,dc=min,dc=io"
	res, err := s.adm.ListAccessKeysLDAP(ctx, dn, "")
	if err != nil {
		c.Fatalf("Unable to list access keys: %v", err)
	}

	epochTime := time.Unix(0, 0).UTC()
	expectedAccKeys := madmin.ListAccessKeysLDAPResp{
		ServiceAccounts: []madmin.ServiceAccountInfo{
			{
				AccessKey:  "u4ccRswj62HV3Ifwima7",
				Expiration: &epochTime,
			},
		},
	}

	if !reflect.DeepEqual(expectedAccKeys, res) {
		c.Fatalf("access keys mismatch: expected: %v, got: %v", expectedAccKeys, res)
	}

	accKeyInfo, err := s.adm.InfoServiceAccount(ctx, "u4ccRswj62HV3Ifwima7")
	if err != nil {
		c.Fatalf("Unable to get service account info: %v", err)
	}
	if accKeyInfo.ParentUser != "uid=svc.algorithm,ou=swengg,dc=min,dc=io" {
		c.Fatalf("parent mismatch: expected: %s, got: %s", "uid=svc.algorithm,ou=swengg,dc=min,dc=io", accKeyInfo.ParentUser)
	}
}

func (s *TestSuiteIAM) TestIAMImport(c *check, exportedContent []byte, caseNum int, content iamTestContent) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	dummyCloser := dummyCloser{bytes.NewReader(exportedContent)}
	err := s.adm.ImportIAM(ctx, dummyCloser)
	if err != nil {
		c.Fatalf("import %d: Unable to import IAM: %v", caseNum, err)
	}

	gotContent := iamTestContent{
		policies:                make(map[string][]byte),
		ldapUserPolicyMappings:  make(map[string][]string),
		ldapGroupPolicyMappings: make(map[string][]string),
	}
	policyContentMap, err := s.adm.ListCannedPolicies(ctx)
	if err != nil {
		c.Fatalf("import %d: Unable to list policies: %v", caseNum, err)
	}
	defaultCannedPolicies := set.CreateStringSet()
	for _, p := range policy.DefaultPolicies {
		defaultCannedPolicies.Add(p.Name)
	}
	for policy, policyBytes := range policyContentMap {
		if defaultCannedPolicies.Contains(policy) {
			continue
		}
		gotContent.policies[policy] = policyBytes
	}

	policyQueryRes, err := s.adm.GetLDAPPolicyEntities(ctx, madmin.PolicyEntitiesQuery{})
	if err != nil {
		c.Fatalf("import %d: Unable to get policy entities: %v", caseNum, err)
	}

	for _, entity := range policyQueryRes.PolicyMappings {
		m := gotContent.ldapUserPolicyMappings
		for _, user := range entity.Users {
			m[user] = append(m[user], entity.Policy)
		}
		m = gotContent.ldapGroupPolicyMappings
		for _, group := range entity.Groups {
			m[group] = append(m[group], entity.Policy)
		}
	}

	{
		// We don't compare the values of the canned policies because server is
		// re-encoding them. (FIXME?)
		for k := range content.policies {
			content.policies[k] = nil
			gotContent.policies[k] = nil
		}
		if !reflect.DeepEqual(content.policies, gotContent.policies) {
			c.Fatalf("import %d: policies mismatch: expected: %v, got: %v", caseNum, content.policies, gotContent.policies)
		}
	}

	if !reflect.DeepEqual(content.ldapUserPolicyMappings, gotContent.ldapUserPolicyMappings) {
		c.Fatalf("import %d: user policy mappings mismatch: expected: %v, got: %v", caseNum, content.ldapUserPolicyMappings, gotContent.ldapUserPolicyMappings)
	}

	if !reflect.DeepEqual(content.ldapGroupPolicyMappings, gotContent.ldapGroupPolicyMappings) {
		c.Fatalf("import %d: group policy mappings mismatch: expected: %v, got: %v", caseNum, content.ldapGroupPolicyMappings, gotContent.ldapGroupPolicyMappings)
	}
}

func (s *TestSuiteIAM) TestLDAPSTS(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Create policy
	policy := "mypolicy"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	ldapID := cr.LDAPIdentity{
		Client:       s.TestSuiteCommon.client,
		STSEndpoint:  s.endPoint,
		LDAPUsername: "dillon",
		LDAPPassword: "dillon",
	}

	_, err = ldapID.Retrieve()
	if err == nil {
		c.Fatalf("Expected to fail to create STS cred with no associated policy!")
	}

	// Attempting to set a non-existent policy should fail.
	userDN := "uid=dillon,ou=people,ou=swengg,dc=min,dc=io"
	_, err = s.adm.AttachPolicyLDAP(ctx, madmin.PolicyAssociationReq{
		Policies: []string{policy + "x"},
		User:     userDN,
	})
	if err == nil {
		c.Fatalf("should not be able to attach non-existent policy")
	}

	userReq := madmin.PolicyAssociationReq{
		Policies: []string{policy},
		User:     userDN,
	}

	if _, err = s.adm.AttachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to attach user policy: %v", err)
	}

	value, err := ldapID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that user listing does not return any entries
	usersList, err := s.adm.ListUsers(ctx)
	if err != nil {
		c.Fatalf("list users should not fail: %v", err)
	}
	if len(usersList) != 1 {
		c.Fatalf("expected user listing output: %v", usersList)
	}
	uinfo := usersList[userDN]
	if uinfo.PolicyName != policy || uinfo.Status != madmin.AccountEnabled {
		c.Fatalf("expected user listing content: %v", uinfo)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that the client cannot remove any objects
	err = minioClient.RemoveObject(ctx, bucket, "someobject", minio.RemoveObjectOptions{})
	if err.Error() != "Access Denied." {
		c.Fatalf("unexpected non-access-denied err: %v", err)
	}

	if _, err = s.adm.DetachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to detach user policy: %v", err)
	}

	_, err = ldapID.Retrieve()
	if err == nil {
		c.Fatalf("Expected to fail to create a user with no associated policy!")
	}

	// Set policy via group and validate policy assignment.
	groupDN := "cn=projectb,ou=groups,ou=swengg,dc=min,dc=io"
	groupReq := madmin.PolicyAssociationReq{
		Policies: []string{policy},
		Group:    groupDN,
	}

	if _, err = s.adm.AttachPolicyLDAP(ctx, groupReq); err != nil {
		c.Fatalf("Unable to attach group policy: %v", err)
	}

	value, err = ldapID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	minioClient, err = minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that the client cannot remove any objects
	err = minioClient.RemoveObject(ctx, bucket, "someobject", minio.RemoveObjectOptions{})
	c.Assert(err.Error(), "Access Denied.")

	if _, err = s.adm.DetachPolicyLDAP(ctx, groupReq); err != nil {
		c.Fatalf("Unable to detach group policy: %v", err)
	}
}

func (s *TestSuiteIAM) TestLDAPUnicodeVariationsLegacyAPI(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Create policy
	policy := "mypolicy"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	ldapID := cr.LDAPIdentity{
		Client:       s.TestSuiteCommon.client,
		STSEndpoint:  s.endPoint,
		LDAPUsername: "svc.algorithm",
		LDAPPassword: "example",
	}

	_, err = ldapID.Retrieve()
	if err == nil {
		c.Fatalf("Expected to fail to create STS cred with no associated policy!")
	}

	mustNormalizeDN := func(dn string) string {
		normalizedDN, err := ldap.NormalizeDN(dn)
		if err != nil {
			c.Fatalf("normalize err: %v", err)
		}
		return normalizedDN
	}

	actualUserDN := mustNormalizeDN("uid=svc.algorithm,OU=swengg,DC=min,DC=io")

	// \uFE52 is the unicode dot SMALL FULL STOP used below:
	userDNWithUnicodeDot := "uid=svc﹒algorithm,OU=swengg,DC=min,DC=io"

	if err = s.adm.SetPolicy(ctx, policy, userDNWithUnicodeDot, false); err != nil {
		c.Fatalf("Unable to set policy: %v", err)
	}

	value, err := ldapID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	usersList, err := s.adm.ListUsers(ctx)
	if err != nil {
		c.Fatalf("list users should not fail: %v", err)
	}
	if len(usersList) != 1 {
		c.Fatalf("expected user listing output: %#v", usersList)
	}
	uinfo := usersList[actualUserDN]
	if uinfo.PolicyName != policy || uinfo.Status != madmin.AccountEnabled {
		c.Fatalf("expected user listing content: %v", uinfo)
	}

	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that the client cannot remove any objects
	err = minioClient.RemoveObject(ctx, bucket, "someobject", minio.RemoveObjectOptions{})
	if err.Error() != "Access Denied." {
		c.Fatalf("unexpected non-access-denied err: %v", err)
	}

	// Remove the policy assignment on the user DN:
	if err = s.adm.SetPolicy(ctx, "", userDNWithUnicodeDot, false); err != nil {
		c.Fatalf("Unable to remove policy setting: %v", err)
	}

	_, err = ldapID.Retrieve()
	if err == nil {
		c.Fatalf("Expected to fail to create a user with no associated policy!")
	}

	// Set policy via group and validate policy assignment.
	actualGroupDN := mustNormalizeDN("cn=project.c,ou=groups,ou=swengg,dc=min,dc=io")
	groupDNWithUnicodeDot := "cn=project﹒c,ou=groups,ou=swengg,dc=min,dc=io"
	if err = s.adm.SetPolicy(ctx, policy, groupDNWithUnicodeDot, true); err != nil {
		c.Fatalf("Unable to attach group policy: %v", err)
	}

	value, err = ldapID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	policyResult, err := s.adm.GetLDAPPolicyEntities(ctx, madmin.PolicyEntitiesQuery{
		Policy: []string{policy},
	})
	if err != nil {
		c.Fatalf("GetLDAPPolicyEntities should not fail: %v", err)
	}
	{
		// Check that the mapping we created exists.
		idx := slices.IndexFunc(policyResult.PolicyMappings, func(e madmin.PolicyEntities) bool {
			return e.Policy == policy && slices.Contains(e.Groups, actualGroupDN)
		})
		if idx < 0 {
			c.Fatalf("expected groupDN (%s) to be present in mapping list: %#v", actualGroupDN, policyResult)
		}
	}

	minioClient, err = minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that the client cannot remove any objects
	err = minioClient.RemoveObject(ctx, bucket, "someobject", minio.RemoveObjectOptions{})
	c.Assert(err.Error(), "Access Denied.")
}

func (s *TestSuiteIAM) TestLDAPUnicodeVariations(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Create policy
	policy := "mypolicy"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	ldapID := cr.LDAPIdentity{
		Client:       s.TestSuiteCommon.client,
		STSEndpoint:  s.endPoint,
		LDAPUsername: "svc.algorithm",
		LDAPPassword: "example",
	}

	_, err = ldapID.Retrieve()
	if err == nil {
		c.Fatalf("Expected to fail to create STS cred with no associated policy!")
	}

	mustNormalizeDN := func(dn string) string {
		normalizedDN, err := ldap.NormalizeDN(dn)
		if err != nil {
			c.Fatalf("normalize err: %v", err)
		}
		return normalizedDN
	}

	actualUserDN := mustNormalizeDN("uid=svc.algorithm,OU=swengg,DC=min,DC=io")

	// \uFE52 is the unicode dot SMALL FULL STOP used below:
	userDNWithUnicodeDot := "uid=svc﹒algorithm,OU=swengg,DC=min,DC=io"

	userReq := madmin.PolicyAssociationReq{
		Policies: []string{policy},
		User:     userDNWithUnicodeDot,
	}

	if _, err = s.adm.AttachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to attach user policy: %v", err)
	}

	value, err := ldapID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	usersList, err := s.adm.ListUsers(ctx)
	if err != nil {
		c.Fatalf("list users should not fail: %v", err)
	}
	if len(usersList) != 1 {
		c.Fatalf("expected user listing output: %#v", usersList)
	}
	uinfo := usersList[actualUserDN]
	if uinfo.PolicyName != policy || uinfo.Status != madmin.AccountEnabled {
		c.Fatalf("expected user listing content: %v", uinfo)
	}

	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that the client cannot remove any objects
	err = minioClient.RemoveObject(ctx, bucket, "someobject", minio.RemoveObjectOptions{})
	if err.Error() != "Access Denied." {
		c.Fatalf("unexpected non-access-denied err: %v", err)
	}

	// Remove the policy assignment on the user DN:

	if _, err = s.adm.DetachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to detach user policy: %v", err)
	}

	_, err = ldapID.Retrieve()
	if err == nil {
		c.Fatalf("Expected to fail to create a user with no associated policy!")
	}

	// Set policy via group and validate policy assignment.
	actualGroupDN := mustNormalizeDN("cn=project.c,ou=groups,ou=swengg,dc=min,dc=io")
	groupDNWithUnicodeDot := "cn=project﹒c,ou=groups,ou=swengg,dc=min,dc=io"
	groupReq := madmin.PolicyAssociationReq{
		Policies: []string{policy},
		Group:    groupDNWithUnicodeDot,
	}

	if _, err = s.adm.AttachPolicyLDAP(ctx, groupReq); err != nil {
		c.Fatalf("Unable to attach group policy: %v", err)
	}

	value, err = ldapID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	policyResult, err := s.adm.GetLDAPPolicyEntities(ctx, madmin.PolicyEntitiesQuery{
		Policy: []string{policy},
	})
	if err != nil {
		c.Fatalf("GetLDAPPolicyEntities should not fail: %v", err)
	}
	{
		// Check that the mapping we created exists.
		idx := slices.IndexFunc(policyResult.PolicyMappings, func(e madmin.PolicyEntities) bool {
			return e.Policy == policy && slices.Contains(e.Groups, actualGroupDN)
		})
		if idx < 0 {
			c.Fatalf("expected groupDN (%s) to be present in mapping list: %#v", actualGroupDN, policyResult)
		}
	}

	minioClient, err = minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that the client cannot remove any objects
	err = minioClient.RemoveObject(ctx, bucket, "someobject", minio.RemoveObjectOptions{})
	c.Assert(err.Error(), "Access Denied.")

	if _, err = s.adm.DetachPolicyLDAP(ctx, groupReq); err != nil {
		c.Fatalf("Unable to detach group policy: %v", err)
	}
}

func (s *TestSuiteIAM) TestLDAPSTSServiceAccounts(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Create policy
	policy := "mypolicy"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	userDN := "uid=dillon,ou=people,ou=swengg,dc=min,dc=io"
	userReq := madmin.PolicyAssociationReq{
		Policies: []string{policy},
		User:     userDN,
	}

	if _, err = s.adm.AttachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to attach user policy: %v", err)
	}

	ldapID := cr.LDAPIdentity{
		Client:       s.TestSuiteCommon.client,
		STSEndpoint:  s.endPoint,
		LDAPUsername: "dillon",
		LDAPPassword: "dillon",
	}

	value, err := ldapID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	// Check that the LDAP sts cred is actually working.
	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Create an madmin client with user creds
	userAdmClient, err := madmin.NewWithOptions(s.endpoint, &madmin.Options{
		Creds:  cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure: s.secure,
	})
	if err != nil {
		c.Fatalf("Err creating user admin client: %v", err)
	}
	userAdmClient.SetCustomTransport(s.TestSuiteCommon.client.Transport)

	// Create svc acc
	cr := c.mustCreateSvcAccount(ctx, value.AccessKeyID, userAdmClient)

	// 1. Check that svc account appears in listing
	c.assertSvcAccAppearsInListing(ctx, userAdmClient, value.AccessKeyID, cr.AccessKey)

	// 2. Check that svc account info can be queried
	c.assertSvcAccInfoQueryable(ctx, userAdmClient, value.AccessKeyID, cr.AccessKey, true)

	// 3. Check S3 access
	c.assertSvcAccS3Access(ctx, s, cr, bucket)

	// 5. Check that service account can be deleted.
	c.assertSvcAccDeletion(ctx, s, userAdmClient, value.AccessKeyID, bucket)

	// 6. Check that service account cannot be created for some other user.
	c.mustNotCreateSvcAccount(ctx, globalActiveCred.AccessKey, userAdmClient)

	// An empty policy must not contaminate an expiring LDAP child credential.
	emptyPolicyCred, err := userAdmClient.AddServiceAccountLDAP(ctx, madmin.AddServiceAccountReq{Policy: []byte("null")})
	if err != nil {
		c.Fatalf("Unable to create empty-policy LDAP service account: %v", err)
	}
	emptyPolicyAdmin := s.getAdminClient(c, emptyPolicyCred.AccessKey, emptyPolicyCred.SecretKey, "")
	expires := UTCNow().Add(time.Hour)
	for _, childPolicy := range [][]byte{nil, []byte("null")} {
		child, err := emptyPolicyAdmin.AddServiceAccountLDAP(ctx, madmin.AddServiceAccountReq{Expiration: &expires, Policy: childPolicy})
		if err != nil {
			c.Fatalf("Unable to create expiring LDAP child: %v", err)
		}
		c.assertSvcAccS3Access(ctx, s, child, bucket)
	}

	// Detach the policy from the user
	if _, err = s.adm.DetachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to detach user policy: %v", err)
	}
}

func (s *TestSuiteIAM) TestLDAPSTSServiceAccountsWithUsername(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := "dillon"
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Create policy
	policy := "mypolicy-username"
	policyBytes := []byte(`{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
	"s3:PutObject",
	"s3:GetObject",
	"s3:ListBucket"
   ],
   "Resource": [
	"arn:aws:s3:::${ldap:username}/*"
   ]
  }
 ]
}`)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	userDN := "uid=dillon,ou=people,ou=swengg,dc=min,dc=io"

	userReq := madmin.PolicyAssociationReq{
		Policies: []string{policy},
		User:     userDN,
	}

	if _, err = s.adm.AttachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to attach user policy: %v", err)
	}

	ldapID := cr.LDAPIdentity{
		Client:       s.TestSuiteCommon.client,
		STSEndpoint:  s.endPoint,
		LDAPUsername: "dillon",
		LDAPPassword: "dillon",
	}

	value, err := ldapID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	// Check that the LDAP sts cred is actually working.
	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Create an madmin client with user creds
	userAdmClient, err := madmin.NewWithOptions(s.endpoint, &madmin.Options{
		Creds:  cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure: s.secure,
	})
	if err != nil {
		c.Fatalf("Err creating user admin client: %v", err)
	}
	userAdmClient.SetCustomTransport(s.TestSuiteCommon.client.Transport)

	// Create svc acc
	cr := c.mustCreateSvcAccount(ctx, value.AccessKeyID, userAdmClient)

	svcClient := s.getUserClient(c, cr.AccessKey, cr.SecretKey, "")

	// 1. Check S3 access for service account ListObjects()
	c.mustListObjects(ctx, svcClient, bucket)

	// 2. Check S3 access for upload
	c.mustUpload(ctx, svcClient, bucket)

	// 3. Check S3 access for download
	c.mustDownload(ctx, svcClient, bucket)

	if _, err = s.adm.DetachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to detach user policy: %v", err)
	}
}

// In this test, the parent users gets their permissions from a group, rather
// than having a policy set directly on them.
func (s *TestSuiteIAM) TestLDAPSTSServiceAccountsWithGroups(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Create policy
	policy := "mypolicy"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	groupDN := "cn=projecta,ou=groups,ou=swengg,dc=min,dc=io"
	userReq := madmin.PolicyAssociationReq{
		Policies: []string{policy},
		Group:    groupDN,
	}

	if _, err = s.adm.AttachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to attach user policy: %v", err)
	}

	ldapID := cr.LDAPIdentity{
		Client:       s.TestSuiteCommon.client,
		STSEndpoint:  s.endPoint,
		LDAPUsername: "dillon",
		LDAPPassword: "dillon",
	}

	value, err := ldapID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	// Check that the LDAP sts cred is actually working.
	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Create an madmin client with user creds
	userAdmClient, err := madmin.NewWithOptions(s.endpoint, &madmin.Options{
		Creds:  cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure: s.secure,
	})
	if err != nil {
		c.Fatalf("Err creating user admin client: %v", err)
	}
	userAdmClient.SetCustomTransport(s.TestSuiteCommon.client.Transport)

	// Create svc acc
	cr := c.mustCreateSvcAccount(ctx, value.AccessKeyID, userAdmClient)

	// 1. Check that svc account appears in listing
	c.assertSvcAccAppearsInListing(ctx, userAdmClient, value.AccessKeyID, cr.AccessKey)

	// 2. Check that svc account info can be queried
	c.assertSvcAccInfoQueryable(ctx, userAdmClient, value.AccessKeyID, cr.AccessKey, true)

	// 3. Check S3 access
	c.assertSvcAccS3Access(ctx, s, cr, bucket)

	// 5. Check that service account can be deleted.
	c.assertSvcAccDeletion(ctx, s, userAdmClient, value.AccessKeyID, bucket)

	// 6. Check that service account cannot be created for some other user.
	c.mustNotCreateSvcAccount(ctx, globalActiveCred.AccessKey, userAdmClient)

	// Detach the user policy
	if _, err = s.adm.DetachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to detach user policy: %v", err)
	}
}

func (s *TestSuiteIAM) TestLDAPCyrillicUser(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userReq := madmin.PolicyAssociationReq{
		Policies: []string{"readwrite"},
		User:     "uid=Пользователь,ou=people,ou=swengg,dc=min,dc=io",
	}

	if _, err := s.adm.AttachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to attach user policy: %v", err)
	}

	cases := []struct {
		username string
		dn       string
	}{
		{
			username: "Пользователь",
			dn:       "uid=Пользователь,ou=people,ou=swengg,dc=min,dc=io",
		},
	}

	conn, err := globalIAMSys.LDAPConfig.LDAP.Connect()
	if err != nil {
		c.Fatalf("LDAP connect failed: %v", err)
	}
	defer conn.Close()

	for i, testCase := range cases {
		ldapID := cr.LDAPIdentity{
			Client:       s.TestSuiteCommon.client,
			STSEndpoint:  s.endPoint,
			LDAPUsername: testCase.username,
			LDAPPassword: "example",
		}

		value, err := ldapID.Retrieve()
		if err != nil {
			c.Fatalf("Expected to generate STS creds, got err: %#v", err)
		}

		// Retrieve the STS account's credential object.
		u, ok := globalIAMSys.GetUser(ctx, value.AccessKeyID)
		if !ok {
			c.Fatalf("Expected to find user %s", value.AccessKeyID)
		}

		if u.Credentials.AccessKey != value.AccessKeyID {
			c.Fatalf("Expected access key %s, got %s", value.AccessKeyID, u.Credentials.AccessKey)
		}

		// Retrieve the credential's claims.
		secret, err := getTokenSigningKey()
		if err != nil {
			c.Fatalf("Error getting token signing key: %v", err)
		}
		claims, err := getClaimsFromTokenWithSecret(value.SessionToken, secret)
		if err != nil {
			c.Fatalf("Error getting claims from token: %v", err)
		}

		// Validate claims.
		dnClaim := claims.MapClaims[ldapActualUser].(string)
		if dnClaim != testCase.dn {
			c.Fatalf("Test %d: unexpected dn claim: %s", i+1, dnClaim)
		}
	}

	if _, err = s.adm.DetachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to detach user policy: %v", err)
	}
}

// Normalized DNs hex-escape every non-ASCII byte, so a user in nested Cyrillic
// OUs has a DN longer than NAME_MAX: 160 bytes of UTF-8 become 384 characters.
// Records named after such a DN can never be stored by the object backend.
// The user is entitled only through a group, as is typical for AD deployments.
func (s *TestSuiteIAM) TestLDAPLongNonASCIIDN(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const (
		username = "Сотрудник"
		parentOU = "ou=Дирекция информационных технологий,ou=people,ou=swengg,dc=min,dc=io"
		childOU  = "ou=Отдел разработки," + parentOU
		userDN   = "uid=" + username + "," + childOU
		groupDN  = "cn=long-dn-staff,ou=groups,ou=swengg,dc=min,dc=io"
	)
	normDN, err := ldap.NormalizeDN(userDN)
	if err != nil {
		c.Fatal(err)
	}
	if len(normDN) <= 255 {
		c.Fatalf("normalized test DN must exceed 255 characters, got %d", len(normDN))
	}

	conn, err := globalIAMSys.LDAPConfig.LDAP.Connect()
	if err != nil {
		c.Fatalf("LDAP connect failed: %v", err)
	}
	defer conn.Close()
	if err = conn.Bind("cn=admin,dc=min,dc=io", "admin"); err != nil {
		c.Fatalf("LDAP admin bind failed: %v", err)
	}
	newEntry := func(dn string, attrs map[string]string) *goldap.AddRequest {
		req := goldap.NewAddRequest(dn, nil)
		for name, value := range attrs {
			req.Attribute(name, []string{value})
		}
		return req
	}
	entries := []*goldap.AddRequest{
		newEntry(parentOU, map[string]string{"objectClass": "organizationalUnit", "ou": "Дирекция информационных технологий"}),
		newEntry(childOU, map[string]string{"objectClass": "organizationalUnit", "ou": "Отдел разработки"}),
		newEntry(userDN, map[string]string{"objectClass": "inetOrgPerson", "uid": username, "cn": username, "sn": username, "userPassword": "example"}),
		newEntry(groupDN, map[string]string{"objectClass": "groupOfNames", "cn": "long-dn-staff", "member": userDN}),
	}
	removeEntries := func() {
		for i := len(entries) - 1; i >= 0; i-- {
			err := conn.Del(goldap.NewDelRequest(entries[i].DN, nil))
			if err != nil && !goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject) {
				c.Errorf("Unable to remove LDAP entry %s: %v", entries[i].DN, err)
			}
		}
	}
	removeEntries() // left over from an interrupted run
	defer removeEntries()
	for _, entry := range entries {
		if err = conn.Add(entry); err != nil {
			c.Fatalf("Unable to add LDAP entry %s: %v", entry.DN, err)
		}
	}

	groupReq := madmin.PolicyAssociationReq{
		Policies: []string{"readwrite"},
		Group:    groupDN,
	}
	if _, err = s.adm.AttachPolicyLDAP(ctx, groupReq); err != nil {
		c.Fatalf("Unable to attach group policy: %v", err)
	}
	defer func() {
		if _, err := s.adm.DetachPolicyLDAP(ctx, groupReq); err != nil {
			c.Errorf("Unable to detach group policy: %v", err)
		}
	}()

	bucket := getRandomBucketName()
	if err = s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	ldapID := cr.LDAPIdentity{
		Client:       s.TestSuiteCommon.client,
		STSEndpoint:  s.endPoint,
		LDAPUsername: username,
		LDAPPassword: "example",
	}
	value, err := ldapID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}
	u, ok := globalIAMSys.GetUser(ctx, value.AccessKeyID)
	if !ok {
		c.Fatalf("Expected to find user %s", value.AccessKeyID)
	}
	if u.Credentials.ParentUser != normDN {
		c.Fatalf("unexpected parent user: %s", u.Credentials.ParentUser)
	}
	c.mustListObjects(ctx, s.getUserClient(c, value.AccessKeyID, value.SecretAccessKey, value.SessionToken), bucket)

	// An access key created by this user inherits the same parent.
	userAdmClient := s.getAdminClient(c, value.AccessKeyID, value.SecretAccessKey, value.SessionToken)
	svc := c.mustCreateSvcAccount(ctx, value.AccessKeyID, userAdmClient)
	c.assertSvcAccS3Access(ctx, s, svc, bucket)
	if err = s.adm.DeleteServiceAccount(ctx, svc.AccessKey); err != nil {
		c.Fatalf("Unable to delete service account: %v", err)
	}
}

func (s *TestSuiteIAM) TestLDAPSlashDN(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	policyReq := madmin.PolicyAssociationReq{
		Policies: []string{"readwrite"},
	}

	cases := []struct {
		username string
		dn       string
		group    string
	}{
		{
			username: "slashuser",
			dn:       "uid=slash/user,ou=people,ou=swengg,dc=min,dc=io",
		},
		{
			username: "dillon",
			dn:       "uid=dillon,ou=people,ou=swengg,dc=min,dc=io",
			group:    "cn=project/d,ou=groups,ou=swengg,dc=min,dc=io",
		},
	}

	conn, err := globalIAMSys.LDAPConfig.LDAP.Connect()
	if err != nil {
		c.Fatalf("LDAP connect failed: %v", err)
	}
	defer conn.Close()

	for i, testCase := range cases {
		if testCase.group != "" {
			policyReq.Group = testCase.group
			policyReq.User = ""
		} else {
			policyReq.User = testCase.dn
			policyReq.Group = ""
		}

		if _, err := s.adm.AttachPolicyLDAP(ctx, policyReq); err != nil {
			c.Fatalf("Unable to attach  policy: %v", err)
		}

		ldapID := cr.LDAPIdentity{
			Client:       s.TestSuiteCommon.client,
			STSEndpoint:  s.endPoint,
			LDAPUsername: testCase.username,
			LDAPPassword: testCase.username,
		}

		value, err := ldapID.Retrieve()
		if err != nil {
			c.Fatalf("Expected to generate STS creds, got err: %#v", err)
		}

		// Retrieve the STS account's credential object.
		u, ok := globalIAMSys.GetUser(ctx, value.AccessKeyID)
		if !ok {
			c.Fatalf("Expected to find user %s", value.AccessKeyID)
		}

		if u.Credentials.AccessKey != value.AccessKeyID {
			c.Fatalf("Expected access key %s, got %s", value.AccessKeyID, u.Credentials.AccessKey)
		}

		// Retrieve the credential's claims.
		secret, err := getTokenSigningKey()
		if err != nil {
			c.Fatalf("Error getting token signing key: %v", err)
		}
		claims, err := getClaimsFromTokenWithSecret(value.SessionToken, secret)
		if err != nil {
			c.Fatalf("Error getting claims from token: %v", err)
		}

		// Validate claims.
		dnClaim := claims.MapClaims[ldapActualUser].(string)
		if dnClaim != testCase.dn {
			c.Fatalf("Test %d: unexpected dn claim: %s", i+1, dnClaim)
		}

		if _, err = s.adm.DetachPolicyLDAP(ctx, policyReq); err != nil {
			c.Fatalf("Unable to detach user policy: %v", err)
		}
	}
}

func (s *TestSuiteIAM) TestLDAPAttributesLookup(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	groupDN := "cn=projectb,ou=groups,ou=swengg,dc=min,dc=io"
	groupReq := madmin.PolicyAssociationReq{
		Policies: []string{"readwrite"},
		Group:    groupDN,
	}

	if _, err := s.adm.AttachPolicyLDAP(ctx, groupReq); err != nil {
		c.Fatalf("Unable to attach user policy: %v", err)
	}

	cases := []struct {
		username           string
		dn                 string
		expectedSSHKeyType string
	}{
		{
			username:           "dillon",
			dn:                 "uid=dillon,ou=people,ou=swengg,dc=min,dc=io",
			expectedSSHKeyType: "ssh-ed25519",
		},
		{
			username:           "liza",
			dn:                 "uid=liza,ou=people,ou=swengg,dc=min,dc=io",
			expectedSSHKeyType: "ssh-rsa",
		},
	}

	conn, err := globalIAMSys.LDAPConfig.LDAP.Connect()
	if err != nil {
		c.Fatalf("LDAP connect failed: %v", err)
	}
	defer conn.Close()

	for i, testCase := range cases {
		ldapID := cr.LDAPIdentity{
			Client:       s.TestSuiteCommon.client,
			STSEndpoint:  s.endPoint,
			LDAPUsername: testCase.username,
			LDAPPassword: testCase.username,
		}

		value, err := ldapID.Retrieve()
		if err != nil {
			c.Fatalf("Expected to generate STS creds, got err: %#v", err)
		}

		// Retrieve the STS account's credential object.
		u, ok := globalIAMSys.GetUser(ctx, value.AccessKeyID)
		if !ok {
			c.Fatalf("Expected to find user %s", value.AccessKeyID)
		}

		if u.Credentials.AccessKey != value.AccessKeyID {
			c.Fatalf("Expected access key %s, got %s", value.AccessKeyID, u.Credentials.AccessKey)
		}

		// Retrieve the credential's claims.
		secret, err := getTokenSigningKey()
		if err != nil {
			c.Fatalf("Error getting token signing key: %v", err)
		}
		claims, err := getClaimsFromTokenWithSecret(value.SessionToken, secret)
		if err != nil {
			c.Fatalf("Error getting claims from token: %v", err)
		}

		// Validate claims. Check if the sshPublicKey claim is present.
		dnClaim := claims.MapClaims[ldapActualUser].(string)
		if dnClaim != testCase.dn {
			c.Fatalf("Test %d: unexpected dn claim: %s", i+1, dnClaim)
		}
		sshPublicKeyClaim := claims.MapClaims[ldapAttribPrefix+"sshPublicKey"].([]any)[0].(string)
		if sshPublicKeyClaim == "" {
			c.Fatalf("Test %d: expected sshPublicKey claim to be present", i+1)
		}
		parts := strings.Split(sshPublicKeyClaim, " ")
		if parts[0] != testCase.expectedSSHKeyType {
			c.Fatalf("Test %d: unexpected sshPublicKey type: %s", i+1, parts[0])
		}
	}

	if _, err = s.adm.DetachPolicyLDAP(ctx, groupReq); err != nil {
		c.Fatalf("Unable to detach group policy: %v", err)
	}
}

func (s *TestSuiteIAM) TestLDAPPolicyEntitiesLookup(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	groupDN := "cn=projectb,ou=groups,ou=swengg,dc=min,dc=io"
	groupPolicy := "readwrite"
	groupReq := madmin.PolicyAssociationReq{
		Policies: []string{groupPolicy},
		Group:    groupDN,
	}
	_, err := s.adm.AttachPolicyLDAP(ctx, groupReq)
	if err != nil {
		c.Fatalf("Unable to attach group policy: %v", err)
	}
	type caseTemplate struct {
		inDN                string
		expectedOutDN       string
		expectedGroupDN     string
		expectedGroupPolicy string
	}
	cases := []caseTemplate{
		{
			inDN:                "uid=dillon,ou=people,ou=swengg,dc=min,dc=io",
			expectedOutDN:       "uid=dillon,ou=people,ou=swengg,dc=min,dc=io",
			expectedGroupDN:     groupDN,
			expectedGroupPolicy: groupPolicy,
		},
	}

	policy := "readonly"
	for _, testCase := range cases {
		userReq := madmin.PolicyAssociationReq{
			Policies: []string{policy},
			User:     testCase.inDN,
		}
		_, err := s.adm.AttachPolicyLDAP(ctx, userReq)
		if err != nil {
			c.Fatalf("Unable to attach policy: %v", err)
		}

		entities, err := s.adm.GetLDAPPolicyEntities(ctx, madmin.PolicyEntitiesQuery{
			Users:  []string{testCase.inDN},
			Policy: []string{policy},
		})
		if err != nil {
			c.Fatalf("Unable to fetch policy entities: %v", err)
		}

		// switch statement to check all the conditions
		switch {
		case len(entities.UserMappings) != 1:
			c.Fatalf("Expected to find exactly one user mapping")
		case entities.UserMappings[0].User != testCase.expectedOutDN:
			c.Fatalf("Expected user DN `%s`, found `%s`", testCase.expectedOutDN, entities.UserMappings[0].User)
		case len(entities.UserMappings[0].Policies) != 1:
			c.Fatalf("Expected exactly one policy attached to user")
		case entities.UserMappings[0].Policies[0] != policy:
			c.Fatalf("Expected attached policy `%s`, found `%s`", policy, entities.UserMappings[0].Policies[0])
		case len(entities.UserMappings[0].MemberOfMappings) != 1:
			c.Fatalf("Expected exactly one group attached to user")
		case entities.UserMappings[0].MemberOfMappings[0].Group != testCase.expectedGroupDN:
			c.Fatalf("Expected attached group `%s`, found `%s`", testCase.expectedGroupDN, entities.UserMappings[0].MemberOfMappings[0].Group)
		case len(entities.UserMappings[0].MemberOfMappings[0].Policies) != 1:
			c.Fatalf("Expected exactly one policy attached to group")
		case entities.UserMappings[0].MemberOfMappings[0].Policies[0] != testCase.expectedGroupPolicy:
			c.Fatalf("Expected attached policy `%s`, found `%s`", testCase.expectedGroupPolicy, entities.UserMappings[0].MemberOfMappings[0].Policies[0])
		}

		_, err = s.adm.DetachPolicyLDAP(ctx, userReq)
		if err != nil {
			c.Fatalf("Unable to detach policy: %v", err)
		}
	}

	_, err = s.adm.DetachPolicyLDAP(ctx, groupReq)
	if err != nil {
		c.Fatalf("Unable to detach group policy: %v", err)
	}
}

func (s *TestSuiteIAM) TestOpenIDSTS(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Generate web identity STS token by interacting with OpenID IDP.
	token, err := MockOpenIDTestUserInteraction(ctx, testAppParams, "dillon@example.io", "dillon")
	if err != nil {
		c.Fatalf("mock user err: %v", err)
	}
	// fmt.Printf("TOKEN: %s\n", token)

	webID := cr.STSWebIdentity{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		GetWebIDTokenExpiry: func() (*cr.WebIdentityToken, error) {
			return &cr.WebIdentityToken{
				Token: token,
			}, nil
		},
	}

	// Create policy - with name as one of the groups in OpenID the user is
	// a member of.
	policy := "projecta"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	value, err := webID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that the client cannot remove any objects
	err = minioClient.RemoveObject(ctx, bucket, "someobject", minio.RemoveObjectOptions{})
	if err.Error() != "Access Denied." {
		c.Fatalf("unexpected non-access-denied err: %v", err)
	}
}

func (s *TestSuiteIAM) TestOpenIDSTSDurationSeconds(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Generate web identity STS token by interacting with OpenID IDP.
	token, err := MockOpenIDTestUserInteraction(ctx, testAppParams, "dillon@example.io", "dillon")
	if err != nil {
		c.Fatalf("mock user err: %v", err)
	}
	// fmt.Printf("TOKEN: %s\n", token)

	webID := cr.STSWebIdentity{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		GetWebIDTokenExpiry: func() (*cr.WebIdentityToken, error) {
			return &cr.WebIdentityToken{
				Token:  token,
				Expiry: 900,
			}, nil
		},
	}

	// Create policy - with name as one of the groups in OpenID the user is
	// a member of.
	policy := "projecta"
	policyTmpl := `{
 "Version": "2012-10-17",
 "Statement": [
  {
    "Effect": "Deny",
    "Action": ["sts:AssumeRoleWithWebIdentity"],
    "Condition": {"NumericGreaterThan": {"sts:DurationSeconds": "%d"}}
  },
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`

	for i, testCase := range []struct {
		durSecs     int
		expectedErr bool
	}{
		{60, true},
		{1800, false},
	} {
		policyBytes := fmt.Appendf(nil, policyTmpl, testCase.durSecs, bucket)
		err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
		if err != nil {
			c.Fatalf("Test %d: policy add error: %v", i+1, err)
		}

		value, err := webID.Retrieve()
		if err != nil && !testCase.expectedErr {
			c.Fatalf("Test %d: Expected to generate STS creds, got err: %#v", i+1, err)
		}
		if err == nil && testCase.expectedErr {
			c.Fatalf("Test %d: An error is unexpected to generate STS creds, got err: %#v", i+1, err)
		}

		if err != nil && testCase.expectedErr {
			continue
		}

		minioClient, err := minio.New(s.endpoint, &minio.Options{
			Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
			Secure:    s.secure,
			Transport: s.TestSuiteCommon.client.Transport,
		})
		if err != nil {
			c.Fatalf("Test %d: Error initializing client: %v", i+1, err)
		}

		c.mustListObjects(ctx, minioClient, bucket)
	}
}

func (s *TestSuiteIAM) TestOpenIDSTSAddUser(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Generate web identity STS token by interacting with OpenID IDP.
	token, err := MockOpenIDTestUserInteraction(ctx, testAppParams, "dillon@example.io", "dillon")
	if err != nil {
		c.Fatalf("mock user err: %v", err)
	}

	webID := cr.STSWebIdentity{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		GetWebIDTokenExpiry: func() (*cr.WebIdentityToken, error) {
			return &cr.WebIdentityToken{
				Token: token,
			}, nil
		},
	}

	// Create policy - with name as one of the groups in OpenID the user is
	// a member of.
	policy := "projecta"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	value, err := webID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	// Create an madmin client with user creds
	userAdmClient, err := madmin.NewWithOptions(s.endpoint, &madmin.Options{
		Creds:  cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure: s.secure,
	})
	if err != nil {
		c.Fatalf("Err creating user admin client: %v", err)
	}
	userAdmClient.SetCustomTransport(s.TestSuiteCommon.client.Transport)

	c.mustNotCreateIAMUser(ctx, userAdmClient)

	// Create admin user policy.
	policyBytes = []byte(`{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "admin:*"
   ]
  }
 ]
}`)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	cr := c.mustCreateIAMUser(ctx, userAdmClient)

	userInfo := c.mustGetIAMUserInfo(ctx, userAdmClient, cr.AccessKey)
	c.Assert(userInfo.Status, madmin.AccountEnabled)
}

func (s *TestSuiteIAM) TestOpenIDServiceAcc(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Generate web identity STS token by interacting with OpenID IDP.
	token, err := MockOpenIDTestUserInteraction(ctx, testAppParams, "dillon@example.io", "dillon")
	if err != nil {
		c.Fatalf("mock user err: %v", err)
	}

	webID := cr.STSWebIdentity{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		GetWebIDTokenExpiry: func() (*cr.WebIdentityToken, error) {
			return &cr.WebIdentityToken{
				Token: token,
			}, nil
		},
	}

	// Create policy - with name as one of the groups in OpenID the user is
	// a member of.
	policy := "projecta"
	policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject",
    "s3:ListBucket"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
	err = s.adm.AddCannedPolicy(ctx, policy, policyBytes)
	if err != nil {
		c.Fatalf("policy add error: %v", err)
	}

	value, err := webID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	// Create an madmin client with user creds
	userAdmClient, err := madmin.NewWithOptions(s.endpoint, &madmin.Options{
		Creds:  cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure: s.secure,
	})
	if err != nil {
		c.Fatalf("Err creating user admin client: %v", err)
	}
	userAdmClient.SetCustomTransport(s.TestSuiteCommon.client.Transport)

	// Create svc acc
	cr := c.mustCreateSvcAccount(ctx, value.AccessKeyID, userAdmClient)

	// 1. Check that svc account appears in listing
	c.assertSvcAccAppearsInListing(ctx, userAdmClient, value.AccessKeyID, cr.AccessKey)

	// 2. Check that svc account info can be queried
	c.assertSvcAccInfoQueryable(ctx, userAdmClient, value.AccessKeyID, cr.AccessKey, true)

	// 3. Check S3 access
	c.assertSvcAccS3Access(ctx, s, cr, bucket)

	// 5. Check that service account can be deleted.
	c.assertSvcAccDeletion(ctx, s, userAdmClient, value.AccessKeyID, bucket)

	// 6. Check that service account cannot be created for some other user.
	c.mustNotCreateSvcAccount(ctx, globalActiveCred.AccessKey, userAdmClient)
}

var testAppParams = OpenIDClientAppParams{
	ClientID:     "minio-client-app",
	ClientSecret: "minio-client-app-secret",
	ProviderURL:  "http://127.0.0.1:5556/dex",
	RedirectURL:  "http://127.0.0.1:10000/oauth_callback",
}

const (
	EnvTestOpenIDServer  = "_MINIO_OPENID_TEST_SERVER"
	EnvTestOpenIDServer2 = "_MINIO_OPENID_TEST_SERVER_2"
)

// SetUpOpenIDs - sets up one or more OpenID test servers using the test OpenID
// container and canned data from https://github.com/minio/minio-ldap-testing
//
// Each set of client app params corresponds to a separate openid server, and
// the i-th server in this will be applied the i-th policy in `rolePolicies`. If
// a rolePolicies entry is an empty string, that server will be configured as
// policy-claim based openid server. NOTE that a valid configuration can have a
// policy claim based provider only if it is the only OpenID provider.
func (s *TestSuiteIAM) SetUpOpenIDs(c *check, testApps []OpenIDClientAppParams, rolePolicies []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	for i, testApp := range testApps {
		configCmds := []string{
			fmt.Sprintf("identity_openid:%d", i),
			fmt.Sprintf("config_url=%s/.well-known/openid-configuration", testApp.ProviderURL),
			fmt.Sprintf("client_id=%s", testApp.ClientID),
			fmt.Sprintf("client_secret=%s", testApp.ClientSecret),
			"scopes=openid,groups",
			fmt.Sprintf("redirect_uri=%s", testApp.RedirectURL),
		}
		if rolePolicies[i] != "" {
			configCmds = append(configCmds, fmt.Sprintf("role_policy=%s", rolePolicies[i]))
		} else {
			configCmds = append(configCmds, "claim_name=groups")
		}
		_, err := s.adm.SetConfigKV(ctx, strings.Join(configCmds, " "))
		if err != nil {
			return fmt.Errorf("unable to setup OpenID for tests: %v", err)
		}
	}

	s.RestartIAMSuite(c)
	return nil
}

// SetUpOpenID - expects to setup an OpenID test server using the test OpenID
// container and canned data from https://github.com/minio/minio-ldap-testing
func (s *TestSuiteIAM) SetUpOpenID(c *check, serverAddr string, rolePolicy string) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	configCmds := []string{
		"identity_openid",
		fmt.Sprintf("config_url=%s/.well-known/openid-configuration", serverAddr),
		"client_id=minio-client-app",
		"client_secret=minio-client-app-secret",
		"scopes=openid,groups",
		"redirect_uri=http://127.0.0.1:10000/oauth_callback",
	}
	if rolePolicy != "" {
		configCmds = append(configCmds, fmt.Sprintf("role_policy=%s", rolePolicy))
	} else {
		configCmds = append(configCmds, "claim_name=groups")
	}
	_, err := s.adm.SetConfigKV(ctx, strings.Join(configCmds, " "))
	if err != nil {
		c.Fatalf("unable to setup OpenID for tests: %v", err)
	}

	s.RestartIAMSuite(c)
}

func TestIAMWithOpenIDServerSuite(t *testing.T) {
	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				openIDServer := os.Getenv(EnvTestOpenIDServer)
				if openIDServer == "" {
					c.Skip("Skipping OpenID test as no OpenID server is provided.")
				}

				suite.SetUpSuite(c)
				suite.SetUpOpenID(c, openIDServer, "")
				suite.TestOpenIDSTS(c)
				suite.TestOpenIDSTSDurationSeconds(c)
				suite.TestOpenIDServiceAcc(c)
				suite.TestOpenIDSTSAddUser(c)
				suite.TearDownSuite(c)
			},
		)
	}
}

func TestIAMWithOpenIDWithRolePolicyServerSuite(t *testing.T) {
	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				openIDServer := os.Getenv(EnvTestOpenIDServer)
				if openIDServer == "" {
					c.Skip("Skipping OpenID test as no OpenID server is provided.")
				}

				suite.SetUpSuite(c)
				suite.SetUpOpenID(c, openIDServer, "readwrite")
				suite.TestOpenIDSTSWithRolePolicy(c, testRoleARNs[0], testRoleMap[testRoleARNs[0]])
				suite.TestOpenIDServiceAccWithRolePolicy(c)
				suite.TearDownSuite(c)
			},
		)
	}
}

func TestIAMWithOpenIDWithRolePolicyWithPolicyVariablesServerSuite(t *testing.T) {
	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				openIDServer := os.Getenv(EnvTestOpenIDServer)
				if openIDServer == "" {
					c.Skip("Skipping OpenID test as no OpenID server is provided.")
				}

				suite.SetUpSuite(c)
				suite.SetUpOpenID(c, openIDServer, "projecta,projectb,projectaorb")
				suite.TestOpenIDSTSWithRolePolicyWithPolVar(c, testRoleARNs[0], testRoleMap[testRoleARNs[0]])
				suite.TearDownSuite(c)
			},
		)
	}
}

const (
	testRoleARN  = "arn:minio:iam:::role/nOybJqMNzNmroqEKq5D0EUsRZw0"
	testRoleARN2 = "arn:minio:iam:::role/domXb70kze7Ugc1SaxaeFchhLP4"
)

var (
	testRoleARNs = []string{testRoleARN, testRoleARN2}

	// Load test client app and test role mapping depending on test
	// environment.
	testClientApps, testRoleMap = func() ([]OpenIDClientAppParams, map[string]OpenIDClientAppParams) {
		var apps []OpenIDClientAppParams
		m := map[string]OpenIDClientAppParams{}

		openIDServer := os.Getenv(EnvTestOpenIDServer)
		if openIDServer != "" {
			apps = append(apps, OpenIDClientAppParams{
				ClientID:     "minio-client-app",
				ClientSecret: "minio-client-app-secret",
				ProviderURL:  openIDServer,
				RedirectURL:  "http://127.0.0.1:10000/oauth_callback",
			})
			m[testRoleARNs[len(apps)-1]] = apps[len(apps)-1]
		}

		openIDServer2 := os.Getenv(EnvTestOpenIDServer2)
		if openIDServer2 != "" {
			apps = append(apps, OpenIDClientAppParams{
				ClientID:     "minio-client-app-2",
				ClientSecret: "minio-client-app-secret-2",
				ProviderURL:  openIDServer2,
				RedirectURL:  "http://127.0.0.1:10000/oauth_callback",
			})
			m[testRoleARNs[len(apps)-1]] = apps[len(apps)-1]
		}

		return apps, m
	}()
)

func (s *TestSuiteIAM) TestOpenIDSTSWithRolePolicy(c *check, roleARN string, clientApp OpenIDClientAppParams) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Generate web identity JWT by interacting with OpenID IDP.
	token, err := MockOpenIDTestUserInteraction(ctx, clientApp, "dillon@example.io", "dillon")
	if err != nil {
		c.Fatalf("mock user err: %v", err)
	}

	// Generate STS credential.
	webID := cr.STSWebIdentity{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		GetWebIDTokenExpiry: func() (*cr.WebIdentityToken, error) {
			return &cr.WebIdentityToken{
				Token: token,
			}, nil
		},
		RoleARN: roleARN,
	}

	value, err := webID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}
	// fmt.Printf("value: %#v\n", value)

	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)
}

func (s *TestSuiteIAM) TestOpenIDServiceAccWithRolePolicy(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Generate web identity STS token by interacting with OpenID IDP.
	token, err := MockOpenIDTestUserInteraction(ctx, testAppParams, "dillon@example.io", "dillon")
	if err != nil {
		c.Fatalf("mock user err: %v", err)
	}

	webID := cr.STSWebIdentity{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		GetWebIDTokenExpiry: func() (*cr.WebIdentityToken, error) {
			return &cr.WebIdentityToken{
				Token: token,
			}, nil
		},
		RoleARN: testRoleARN,
	}

	value, err := webID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	// Create an madmin client with user creds
	userAdmClient, err := madmin.NewWithOptions(s.endpoint, &madmin.Options{
		Creds:  cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure: s.secure,
	})
	if err != nil {
		c.Fatalf("Err creating user admin client: %v", err)
	}
	userAdmClient.SetCustomTransport(s.TestSuiteCommon.client.Transport)

	// Create svc acc
	cr := c.mustCreateSvcAccount(ctx, value.AccessKeyID, userAdmClient)

	// 1. Check that svc account appears in listing
	c.assertSvcAccAppearsInListing(ctx, userAdmClient, value.AccessKeyID, cr.AccessKey)

	// 2. Check that svc account info can be queried
	c.assertSvcAccInfoQueryable(ctx, userAdmClient, value.AccessKeyID, cr.AccessKey, true)

	// 3. Check S3 access
	c.assertSvcAccS3Access(ctx, s, cr, bucket)

	// 5. Check that service account can be deleted.
	c.assertSvcAccDeletion(ctx, s, userAdmClient, value.AccessKeyID, bucket)
}

// Constants for Policy Variables test.
var (
	policyProjectA = `{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                        "s3:GetBucketLocation",
                        "s3:ListAllMyBuckets"
                      ],
            "Resource": "arn:aws:s3:::*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::projecta",
                "arn:aws:s3:::projecta/*"
            ],
            "Condition": {
                "ForAnyValue:StringEquals": {
                    "jwt:groups": [
                        "projecta"
                    ]
                }
            }
        }
    ]
}
`
	policyProjectB = `{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                        "s3:GetBucketLocation",
                        "s3:ListAllMyBuckets"
                      ],
            "Resource": "arn:aws:s3:::*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::projectb",
                "arn:aws:s3:::projectb/*"
            ],
            "Condition": {
                "ForAnyValue:StringEquals": {
                    "jwt:groups": [
                        "projectb"
                    ]
                }
            }
        }
    ]
}
`
	policyProjectAorB = `{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                        "s3:GetBucketLocation",
                        "s3:ListAllMyBuckets"
                      ],
            "Resource": "arn:aws:s3:::*"
        },
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::projectaorb",
                "arn:aws:s3:::projectaorb/*"
            ],
            "Condition": {
                "ForAnyValue:StringEquals": {
                    "jwt:groups": [
                        "projecta",
                        "projectb"
                    ]
                }
            }
        }
    ]
}`

	policyProjectsMap = map[string]string{
		// grants access to bucket `projecta` if user is in group `projecta`
		"projecta": policyProjectA,

		// grants access to bucket `projectb` if user is in group `projectb`
		"projectb": policyProjectB,

		// grants access to bucket `projectaorb` if user is in either group
		// `projecta` or `projectb`
		"projectaorb": policyProjectAorB,
	}
)

func (s *TestSuiteIAM) TestOpenIDSTSWithRolePolicyWithPolVar(c *check, roleARN string, clientApp OpenIDClientAppParams) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create project buckets
	buckets := []string{"projecta", "projectb", "projectaorb", "other"}
	for _, bucket := range buckets {
		err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
		if err != nil {
			c.Fatalf("bucket create error: %v", err)
		}
	}

	// Create policies
	for polName, polContent := range policyProjectsMap {
		err := s.adm.AddCannedPolicy(ctx, polName, []byte(polContent))
		if err != nil {
			c.Fatalf("policy add error: %v", err)
		}
	}

	makeSTSClient := func(user, password string) *minio.Client {
		// Generate web identity JWT by interacting with OpenID IDP.
		token, err := MockOpenIDTestUserInteraction(ctx, clientApp, user, password)
		if err != nil {
			c.Fatalf("mock user err: %v", err)
		}

		// Generate STS credential.
		webID := cr.STSWebIdentity{
			Client:      s.TestSuiteCommon.client,
			STSEndpoint: s.endPoint,
			GetWebIDTokenExpiry: func() (*cr.WebIdentityToken, error) {
				return &cr.WebIdentityToken{
					Token: token,
				}, nil
			},
			RoleARN: roleARN,
		}

		value, err := webID.Retrieve()
		if err != nil {
			c.Fatalf("Expected to generate STS creds, got err: %#v", err)
		}
		// fmt.Printf("value: %#v\n", value)

		minioClient, err := minio.New(s.endpoint, &minio.Options{
			Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
			Secure:    s.secure,
			Transport: s.TestSuiteCommon.client.Transport,
		})
		if err != nil {
			c.Fatalf("Error initializing client: %v", err)
		}

		return minioClient
	}

	// user dillon's groups attribute is ["projecta", "projectb"]
	dillonClient := makeSTSClient("dillon@example.io", "dillon")
	// Validate client's permissions
	c.mustListBuckets(ctx, dillonClient)
	c.mustListObjects(ctx, dillonClient, "projecta")
	c.mustListObjects(ctx, dillonClient, "projectb")
	c.mustListObjects(ctx, dillonClient, "projectaorb")
	c.mustNotListObjects(ctx, dillonClient, "other")

	// this user's groups attribute is ["projectb"]
	lisaClient := makeSTSClient("ejones@example.io", "liza")
	// Validate client's permissions
	c.mustListBuckets(ctx, lisaClient)
	c.mustNotListObjects(ctx, lisaClient, "projecta")
	c.mustListObjects(ctx, lisaClient, "projectb")
	c.mustListObjects(ctx, lisaClient, "projectaorb")
	c.mustNotListObjects(ctx, lisaClient, "other")
}

func TestIAMWithOpenIDMultipleConfigsValidation1(t *testing.T) {
	openIDServer := os.Getenv(EnvTestOpenIDServer)
	openIDServer2 := os.Getenv(EnvTestOpenIDServer2)
	if openIDServer == "" || openIDServer2 == "" {
		t.Skip("Skipping OpenID test as enough OpenID servers are not provided.")
	}
	testApps := testClientApps

	rolePolicies := []string{
		"", // Treated as claim-based provider as no role policy is given.
		"readwrite",
	}

	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				suite.SetUpSuite(c)
				defer suite.TearDownSuite(c)

				err := suite.SetUpOpenIDs(c, testApps, rolePolicies)
				if err != nil {
					c.Fatalf("config with 1 claim based and 1 role based provider should pass but got: %v", err)
				}
			},
		)
	}
}

func TestIAMWithOpenIDMultipleConfigsValidation2(t *testing.T) {
	openIDServer := os.Getenv(EnvTestOpenIDServer)
	openIDServer2 := os.Getenv(EnvTestOpenIDServer2)
	if openIDServer == "" || openIDServer2 == "" {
		t.Skip("Skipping OpenID test as enough OpenID servers are not provided.")
	}
	testApps := testClientApps

	rolePolicies := []string{
		"", // Treated as claim-based provider as no role policy is given.
		"", // Treated as claim-based provider as no role policy is given.
	}

	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				suite.SetUpSuite(c)
				defer suite.TearDownSuite(c)

				err := suite.SetUpOpenIDs(c, testApps, rolePolicies)
				if err == nil {
					c.Fatalf("config with 2 claim based provider should fail")
				}
			},
		)
	}
}

func TestIAMWithOpenIDWithMultipleRolesServerSuite(t *testing.T) {
	openIDServer := os.Getenv(EnvTestOpenIDServer)
	openIDServer2 := os.Getenv(EnvTestOpenIDServer2)
	if openIDServer == "" || openIDServer2 == "" {
		t.Skip("Skipping OpenID test as enough OpenID servers are not provided.")
	}
	testApps := testClientApps

	rolePolicies := []string{
		"consoleAdmin",
		"readwrite",
	}

	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				suite.SetUpSuite(c)
				err := suite.SetUpOpenIDs(c, testApps, rolePolicies)
				if err != nil {
					c.Fatalf("Error setting up openid providers for tests: %v", err)
				}
				suite.TestOpenIDSTSWithRolePolicy(c, testRoleARNs[0], testRoleMap[testRoleARNs[0]])
				suite.TestOpenIDSTSWithRolePolicy(c, testRoleARNs[1], testRoleMap[testRoleARNs[1]])
				suite.TestOpenIDServiceAccWithRolePolicy(c)
				suite.TearDownSuite(c)
			},
		)
	}
}

// Access Management Plugin tests
func TestIAM_AMPWithOpenIDWithMultipleRolesServerSuite(t *testing.T) {
	openIDServer := os.Getenv(EnvTestOpenIDServer)
	openIDServer2 := os.Getenv(EnvTestOpenIDServer2)
	if openIDServer == "" || openIDServer2 == "" {
		t.Skip("Skipping OpenID test as enough OpenID servers are not provided.")
	}
	testApps := testClientApps

	rolePolicies := []string{
		"consoleAdmin",
		"readwrite",
	}

	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				suite.SetUpSuite(c)
				defer suite.TearDownSuite(c)

				err := suite.SetUpOpenIDs(c, testApps, rolePolicies)
				if err != nil {
					c.Fatalf("Error setting up openid providers for tests: %v", err)
				}

				suite.SetUpAccMgmtPlugin(c)

				suite.TestOpenIDSTSWithRolePolicyUnderAMP(c, testRoleARNs[0], testRoleMap[testRoleARNs[0]])
				suite.TestOpenIDSTSWithRolePolicyUnderAMP(c, testRoleARNs[1], testRoleMap[testRoleARNs[1]])
				suite.TestOpenIDServiceAccWithRolePolicyUnderAMP(c)
			},
		)
	}
}

func (s *TestSuiteIAM) TestOpenIDSTSWithRolePolicyUnderAMP(c *check, roleARN string, clientApp OpenIDClientAppParams) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Generate web identity JWT by interacting with OpenID IDP.
	token, err := MockOpenIDTestUserInteraction(ctx, clientApp, "dillon@example.io", "dillon")
	if err != nil {
		c.Fatalf("mock user err: %v", err)
	}

	// Generate STS credential.
	webID := cr.STSWebIdentity{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		GetWebIDTokenExpiry: func() (*cr.WebIdentityToken, error) {
			return &cr.WebIdentityToken{
				Token: token,
			}, nil
		},
		RoleARN: roleARN,
	}

	value, err := webID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}
	// fmt.Printf("value: %#v\n", value)

	minioClient, err := minio.New(s.endpoint, &minio.Options{
		Creds:     cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure:    s.secure,
		Transport: s.TestSuiteCommon.client.Transport,
	})
	if err != nil {
		c.Fatalf("Error initializing client: %v", err)
	}

	// Validate that the client from sts creds can access the bucket.
	c.mustListObjects(ctx, minioClient, bucket)

	// Validate that the client from STS creds cannot upload any object as
	// it is denied by the plugin.
	c.mustNotUpload(ctx, minioClient, bucket)
}

func (s *TestSuiteIAM) TestOpenIDServiceAccWithRolePolicyUnderAMP(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bucket := getRandomBucketName()
	err := s.client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	if err != nil {
		c.Fatalf("bucket create error: %v", err)
	}

	// Generate web identity STS token by interacting with OpenID IDP.
	token, err := MockOpenIDTestUserInteraction(ctx, testAppParams, "dillon@example.io", "dillon")
	if err != nil {
		c.Fatalf("mock user err: %v", err)
	}

	webID := cr.STSWebIdentity{
		Client:      s.TestSuiteCommon.client,
		STSEndpoint: s.endPoint,
		GetWebIDTokenExpiry: func() (*cr.WebIdentityToken, error) {
			return &cr.WebIdentityToken{
				Token: token,
			}, nil
		},
		RoleARN: testRoleARN,
	}

	value, err := webID.Retrieve()
	if err != nil {
		c.Fatalf("Expected to generate STS creds, got err: %#v", err)
	}

	// Create an madmin client with user creds
	userAdmClient, err := madmin.NewWithOptions(s.endpoint, &madmin.Options{
		Creds:  cr.NewStaticV4(value.AccessKeyID, value.SecretAccessKey, value.SessionToken),
		Secure: s.secure,
	})
	if err != nil {
		c.Fatalf("Err creating user admin client: %v", err)
	}
	userAdmClient.SetCustomTransport(s.TestSuiteCommon.client.Transport)

	// Create svc acc
	cr := c.mustCreateSvcAccount(ctx, value.AccessKeyID, userAdmClient)

	// 1. Check that svc account appears in listing
	c.assertSvcAccAppearsInListing(ctx, userAdmClient, value.AccessKeyID, cr.AccessKey)

	// 2. Check that svc account info can be queried
	c.assertSvcAccInfoQueryable(ctx, userAdmClient, value.AccessKeyID, cr.AccessKey, true)

	// 3. Check S3 access
	c.assertSvcAccS3Access(ctx, s, cr, bucket)
	// 3.1 Validate that the client from STS creds cannot upload any object as
	// it is denied by the plugin.
	c.mustNotUpload(ctx, s.getUserClient(c, cr.AccessKey, cr.SecretKey, ""), bucket)

	// Check that session policies do not apply - as policy enforcement is
	// delegated to plugin.
	{
		svcAK, svcSK := mustGenerateCredentials(c)

		// This policy does not allow listing objects.
		policyBytes := fmt.Appendf(nil, `{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": [
    "s3:PutObject",
    "s3:GetObject"
   ],
   "Resource": [
    "arn:aws:s3:::%s/*"
   ]
  }
 ]
}`, bucket)
		cr, err := userAdmClient.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
			Policy:     policyBytes,
			TargetUser: value.AccessKeyID,
			AccessKey:  svcAK,
			SecretKey:  svcSK,
		})
		if err != nil {
			c.Fatalf("Unable to create svc acc: %v", err)
		}
		svcClient := s.getUserClient(c, cr.AccessKey, cr.SecretKey, "")
		// Though the attached policy does not allow listing, it will be
		// ignored because the plugin allows it.
		c.mustListObjects(ctx, svcClient, bucket)
	}

	// 4. Check that service account's secret key and account status can be
	// updated.
	c.assertSvcAccSecretKeyAndStatusUpdate(ctx, s, userAdmClient, value.AccessKeyID, bucket)

	// 5. Check that service account can be deleted.
	c.assertSvcAccDeletion(ctx, s, userAdmClient, value.AccessKeyID, bucket)
}

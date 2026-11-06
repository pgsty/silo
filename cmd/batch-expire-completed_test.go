// Copyright (c) 2026 PGSTY
//
// This file is part of Silo Object Storage stack
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
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	"go.yaml.in/yaml/v3"
)

// A completed expire job is not run again when the server restarts, as
// replication and key rotation jobs are not: in particular it is not checked
// against its submitter again, which could turn it into a failed job.

// An expire job that completed before the upgrade records no submitter.
func TestBatchExpireCompletedLegacyStaysComplete(t *testing.T) {
	f := newBatchAuthzFixture(t)
	older := f.putVersions(t, "data/a")
	job := &BatchJobRequest{}
	mustIAM(t, yaml.Unmarshal([]byte(f.expireYAML("")), job))
	job.ID = "expire-legacydone" + getKeySeparator() + "0"
	job.User = globalActiveCred.AccessKey
	job.Started = time.Now()
	mustIAM(t, job.save(f.ctx, f.obj))
	ri := &batchJobInfo{JobID: job.ID, JobType: string(job.Type()), StartTime: job.Started, Complete: true, Objects: 3}
	mustIAM(t, ri.updateAfter(f.ctx, f.obj, 0, *job))

	loaded := &BatchJobRequest{}
	mustIAM(t, loaded.load(f.ctx, f.obj, getJobPath(*job)))
	f.run(t, loaded) // resumed after a restart
	got := f.jobInfo(t, job)
	if !got.Complete || got.Failed || got.FailureReason != "" {
		t.Fatalf("complete=%v failed=%v reason=%q, want the completed state kept", got.Complete, got.Failed, got.FailureReason)
	}
	if !f.versionExists(t, "data/a", older) {
		t.Error("a completed job ran again")
	}
}

// A new expire job completed with a temporary credential that has expired
// since.
func TestBatchExpireCompletedAfterCredentialExpiry(t *testing.T) {
	f := newBatchAuthzFixture(t)
	batchAuthzPolicy(f.ctx, t, f.sys, "batch-full", batchAuthzFullAccess)
	parent := iamAdminUser(f.ctx, t, f.sys, "batch-parent", "batch-full")
	cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{parentClaim: parent.AccessKey, "exp": UTCNow().Add(3 * time.Second).Unix()}, globalActiveCred.SecretKey)
	mustIAM(t, err)
	cred.ParentUser = parent.AccessKey
	_, err = f.sys.SetTempUser(f.ctx, cred.AccessKey, cred, "")
	mustIAM(t, err)
	older := f.putVersions(t, "data/a")
	rec, job := f.submit(t, cred, f.expireYAML(""))
	if job == nil {
		t.Fatalf("submission status %d: %s", rec.Code, rec.Body.String())
	}
	f.run(t, job)
	if f.versionExists(t, "data/a", older) {
		t.Fatal("the job did not expire the older version")
	}
	if ri := f.jobInfo(t, job); !ri.Complete {
		t.Fatalf("complete=%v failed=%v", ri.Complete, ri.Failed)
	}
	time.Sleep(time.Until(cred.Expiration) + time.Second)

	loaded := &BatchJobRequest{}
	mustIAM(t, loaded.load(f.ctx, f.obj, getJobPath(*job)))
	f.run(t, loaded) // resumed after a restart
	if ri := f.jobInfo(t, job); !ri.Complete || ri.Failed || ri.FailureReason != "" {
		t.Errorf("complete=%v failed=%v reason=%q after a restart, want the completed state kept", ri.Complete, ri.Failed, ri.FailureReason)
	}

	// Control: a job that did not complete is still refused once its
	// credential has expired.
	f.putVersions(t, "data/b")
	pending := &BatchJobRequest{}
	mustIAM(t, yaml.Unmarshal([]byte(f.expireYAML("")), pending))
	pending.ID = "expire-pending" + getKeySeparator() + "0"
	pending.User = cred.AccessKey
	pending.Started = time.Now()
	pending.Submitter = loaded.Submitter
	mustIAM(t, pending.save(f.ctx, f.obj))
	f.run(t, pending)
	if ri := f.jobInfo(t, pending); ri.Complete || !ri.Failed || ri.FailureReason == "" {
		t.Errorf("pending job with an expired submitter: complete=%v failed=%v reason=%q, want refused", ri.Complete, ri.Failed, ri.FailureReason)
	}
}

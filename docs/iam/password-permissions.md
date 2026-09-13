# Password and user-management permissions

> **Release boundary, 2026-09-13:** this guide describes Server main, paired with
> silo-pkg v3.14.0 and Console source `417559bb2c97` or its accepted successor.
> The latest published Server 20260903 and Console v2.4.0 do not contain this
> split. The pkg v3.14.0 and mcli 20260913 releases alone do not change an old
> Server's authorization. See [the component matrix](https://silo.pgsty.com/compatibility/versions/).

**Breaking change: the password-permission split changes the meaning of
existing IAM policies.** The same stored policy can authorize a request after
this update that it denied before, or deny a request it previously authorized.
This is a deliberate authorization change from adopting
[minio/pkg #262](https://github.com/minio/pkg/pull/262), independent of the
minio-go SDK update. It must be called out as a breaking change in the release
that first includes it; it is not a transparent dependency refresh.

SILO separates a user's own password change from creating users or resetting
another user's password. The same `add-user` administration endpoint and mcli
commands continue to work; the authenticated caller and target access key
determine which permission is checked.

| Request | Permission | Evaluation |
| --- | --- | --- |
| Change the caller's own password | `admin:ChangeMyPassword` | Allowed for an internal user with an attached policy unless explicitly denied. |
| Create another user or reset another user's password | `admin:CreateUser` | Requires an explicit Allow; an explicit Deny wins. |

The Console's Change Password button uses `admin:ChangeMyPassword`.
`admin:CreateUser` continues to control user administration. The password change
still requires the current password. STS and service-account credentials cannot
change their parent user's password; root credentials and external identity
provider passwords remain outside this endpoint.

## What changes and why

Previously, both operations checked `admin:CreateUser`. Changing one's own
password used an implicit grant unless that action was explicitly denied;
managing other users required an explicit Allow. The split retains these two
evaluation rules but checks `admin:ChangeMyPassword` for the caller's password.
It lets an operator independently control password changes and user
administration. This is a policy-design choice, not a required mitigation for
the SDK signing or region-compatibility fixes.

The following cases assume an internal user with an attached policy, matching
statement conditions, and no other applicable grants or denies:

| Existing policy | Own password before | Own password after | Create/reset another user, before and after |
| --- | --- | --- | --- |
| S3 read grant only | Allowed | Allowed | Denied |
| `Deny admin:CreateUser` | Denied | **Allowed** | Denied |
| `Deny admin:ChangeMyPassword` | Allowed | **Denied** | Denied |
| `Allow admin:CreateUser` | Allowed | Allowed | Allowed |
| `Allow admin:CreateUser` plus `Deny admin:ChangeMyPassword` | Allowed | **Denied** | Allowed |
| Deny both actions, or `Deny admin:*` | Denied | Denied | Denied |

Wildcard denies that match `admin:CreateUser` but do not match
`admin:ChangeMyPassword`, such as `admin:Create*`, have the same password
compatibility change as the explicit CreateUser deny. An Allow never overrides
a matching Deny. Granting only `admin:ChangeMyPassword` does not grant user
administration.

The policy JSON format, stored documents and endpoint are retained, but that
does not preserve their authorization semantics. This update does not rewrite
saved policies or provide a switch that restores the old action mapping.

## Preserve the behavior of existing policies

A saved `Deny admin:CreateUser` still prevents user creation and password resets
for other users. It no longer prevents the caller from changing their own
password. If an existing policy used that deny to lock the caller's password,
add `admin:ChangeMyPassword` to the **same Deny statement before upgrading**.
For example, change that statement's action list to:

```json
{
  "Effect": "Deny",
  "Action": ["admin:CreateUser", "admin:ChangeMyPassword"]
}
```

This is a statement fragment, not a replacement for the entire policy.
Preserve its other actions, resource scope and conditions, and all other
statements. Check policies attached through groups as well as directly to users.
The preceding SILO package version already recognizes both action names, so
this dual deny can be prepared before the Server upgrade. Saved policy files
are not migrated automatically; the operator must apply this change where the
old password restriction is intended.

To adopt the new split and lock only the caller's password while allowing
separately granted user administration, deny only `admin:ChangeMyPassword`.
That finer distinction is enforced only by Servers containing this change.

## Built-in read-only policies

The built-in `readonly` policy now grants its original S3 read operations
without its previous CreateUser deny. This has two compatibility effects:

- A user of the old `readonly` policy could not change their own password; with
  the split they can, unless another applicable statement denies
  `admin:ChangeMyPassword`.
- The old built-in `readonly` deny overrode a separate CreateUser Allow. The
  new built-in definition allows that independently granted user administration.
  This can broaden effective permissions for users with both policies attached.

The added `consolereadonly` policy also grants ListBucket for Console browsing
and follows the new split. Neither read-only policy grants user administration
or S3 writes on its own. Their S3 permissions do not implicitly lock passwords.

Saved policies and user overrides of canned policies are preserved on upgrade.
A saved copy of the old read-only policy retains its CreateUser deny and still
blocks a separate CreateUser Allow, even though it no longer blocks self-service
password changes. Where no saved override exists, Server uses the updated
built-in definition. Review the effective policy documents rather than assuming
every policy named `readonly` has the same contents. To retain both old
restrictions, attach a policy denying both actions or retain the saved readonly
override and add ChangeMyPassword to its existing deny.

## Console and package callers

`silo-pkg`'s `Policy.IsAllowedActions` now reports `admin:ChangeMyPassword` as
implicit unless denied, and reports `admin:CreateUser` only when explicitly
allowed. Its Go signature and the Go compatibility floor are unchanged, but
its returned capabilities change. Console and other consumers must stop using
the CreateUser capability as a proxy for permission to change one's own password.

## Coordinated upgrade and rollback

Upgrade SILO Server, silo-pkg and Console together, including the Console
embedded in Server. Update mcli's shared package and SDK pins as part of the
same maintained stack. Mixed versions disagree about the self-service action
and may show a button the Server refuses, hide an allowed operation, or fail to
enforce a new password-specific deny on an old Server.

Before upgrading, export the affected user/group policy documents, review the
cases above, and apply both denies wherever the old combined restriction must
survive. Keep both denies throughout a rolling upgrade and any rollback window.
Verify self-service password changes and other-user creation/password resets
with the affected accounts. Complete the Server rollout and update Console
before relying on the new independent permissions.

Rolling back the binaries does not convert policies. An old Server ignores
`Deny admin:ChangeMyPassword` for this endpoint, so that deny alone cannot lock
the password after rollback. Restore or retain the CreateUser deny when the
password must remain locked; on the old Server it will also deny management of
other users. The old Server cannot represent the new combination of allowing
user administration while denying only self-service password changes.

Upstream MinIO compatibility remains best effort; the supported integration
target is `pgsty/silo`.

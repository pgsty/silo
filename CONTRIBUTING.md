# Contributing to Silo

Silo welcomes focused contributions that improve security, reliability,
compatibility, packaging, tests, or maintainability. This repository preserves
MinIO-compatible interfaces and storage formats, so changes must identify and
test any compatibility impact.

## Development Workflow

Fork the current Silo source repository, create a topic branch, and submit a
pull request. Discuss broad or compatibility-sensitive changes in an issue
before implementation.

### Set up a checkout

```sh
git clone https://github.com/pgsty/silo
cd silo
go build -o silo .
./silo --version
```

### Keep the lineage remote separate

```sh
git remote add lineage https://github.com/minio/minio
git fetch lineage
```

Do not merge an upstream branch into a pull request unless the maintainers have
agreed on the scope. Silo intentionally carries a small downstream delta.

### Create your feature branch

Create a separate branch before making code changes:

```
git checkout -b my-new-feature
```

### Test Silo server changes

Before opening a pull request:

- Add or update tests for changed behavior.
- Run `make verifiers`.
- If `make rebrand-guard` reports a changed compatibility set, review the
  listed identifiers; when the change is intended, refresh the baseline with
  `go run ./buildscripts/rebrand-guard --write` and commit
  `buildscripts/rebrand-guard/compat-baseline.json`.
- Run the smallest relevant package tests, then `make test` when practical.
- Run `make build` and confirm the generated executable is `silo`.
- Explain any preserved `MINIO_*`, `minio_*`, `x-minio-*`, `/minio/*`,
  `.minio.sys`, ARN, module/import-path, or serialized compatibility name.

The maintenance branch retains existing storage timeouts, cancellation,
object locking, read-quorum and healing behavior. The normal suite checks local
and RPC timeout/cancellation, remote rollback options, and readability after a
failed partial overwrite. A timeout does not prove that a disk worker stopped
or that a write did not commit.

Stronger mutation lifetime, rollback ownership, generation ordering, strict-read
and cross-pool recovery diagnostics are preserved behind `consistency_strict`.
Compile them with `go test -tags kqueue,dev,consistency_strict ./cmd -run '^$'`
and run individual scenarios explicitly. They describe guarantees outside the
maintenance contract and may fail; report their results separately from the
normal suite. They must not be used to claim distributed fencing or repair of
previously inconsistent objects.

### Commit changes

After verification, commit your changes with a concise message and a DCO
sign-off (see [Licensing of Contributions](#licensing-of-contributions)):

```
git commit -s -am 'Fix object replication retry handling'
```

### Push to the branch

Push your locally committed changes to the remote origin (your fork)

```
git push origin my-new-feature
```

### Create a Pull Request

Pull requests should include motivation, reproduction steps where applicable,
test evidence, compatibility notes, and documentation impact. Public product
documentation is owned by the separate
[`pgsty/silo.pgsty.com`](https://github.com/pgsty/silo.pgsty.com) repository.

## Contributor recognition

Every human issue or pull-request author is recognized in [CONTRIBUTORS.md](CONTRIBUTORS.md),
including open issues, draft PRs, and PRs closed without merging. Merged fixes,
adopted proposals, and reports that lead to fixes receive greater prominence;
first participation guides the remaining order. Work incorporated through a
later PR retains credit without changing the original PR's recorded status.
Security disclosures are credited with the reporter's agreement. DCO sign-off
applies to code commits, not to opening an issue.

## Licensing of Contributions

Code contributions to PGSTY SILO (`pgsty/silo`) are accepted under the
[GNU AGPL v3.0 or later](LICENSE), the same license as the server. Submit issues
and pull requests to this repository's maintainers. No separate Apache-2.0
license grant to SILO or upstream MinIO maintainers is required.

* **No CLA.** We do not ask you to sign a Contributor License Agreement and we
  do not take your copyright. Contributions are accepted inbound=outbound: you
  keep the copyright to your changes and license them under the same
  AGPL-3.0-or-later as the project itself. The maintainers receive no rights
  beyond the project license.

* **DCO sign-off required.** Every commit must carry a
  `Signed-off-by: Your Name <you@example.com>` trailer certifying the
  [Developer Certificate of Origin 1.1](https://developercertificate.org/) —
  your statement that you have the right to submit the code under the project
  license. Sign each commit with:

  ```
  git commit -s
  ```

  Forgot some? Repair your branch with `git rebase --signoff` and force-push.
  CI rejects pull requests containing unsigned commits; the sign-off email
  must match the commit author email. (Lowercase `-s` is the plain-text DCO
  sign-off; cryptographic `-S`/GPG signing is welcome but independent.)

* **Provenance.** Only submit code you are entitled to submit. This matters
  more here than in most projects: Silo carries a downstream delta over an
  upstream code base, and cherry-picks from the lineage remote or other forks
  are routine. When relaying a patch written by someone else, preserve original
  authorship (`git cherry-pick -x`, keep the author field and any existing
  `Signed-off-by` trailers) and add your own sign-off as the person passing it
  along. Never import code from a proprietary distribution.

* **File headers.** Preserve existing copyright and license notices in inherited
  and third-party files. New original files name their actual copyright holders
  and use AGPL-3.0-or-later. Use a header such as the following, then append the
  standard AGPL boilerplate:

  ```
  // Copyright (c) 2026 Your Name
  ```

* **Separately licensed material.** Documentation contributions in `docs/`
  follow its existing [CC BY 4.0 license](docs/LICENSE). Third-party components
  and earlier Apache-2.0 contributions retain their original licenses and
  attribution; this policy does not relicense earlier work.

* **Squash merges** must keep the `Signed-off-by:` trailers in the resulting
  commit message.

* **Authorship and tooling.** The human contributor is the author of the commit
  and the sole signatory of its DCO sign-off. Attribution trailers for
  assistive tooling (for example `Co-Authored-By:` naming an AI assistant) are
  informational only: they record which tools were used, and do not create
  authorship, co-authorship, or any copyright claim. Whoever signs off remains
  responsible for the content of the commit, whatever produced it.

## FAQs

### How does Silo manage dependencies?

Silo uses Go modules. Preserve the compatibility module and import paths in
`go.mod`; downstream forks are selected with explicit `replace` directives.

- Run `go get foo/bar` in the source folder to add the dependency to `go.mod` file.

To remove a dependency

- Edit your code and remove the import reference.
- Run `go mod tidy` in the source folder to remove dependency from `go.mod` file.

### What are the coding guidelines?

Follow the existing Go style, run `gofmt` on changed Go files, and keep changes
compact. See the Go project's [code review comments](https://go.dev/wiki/CodeReviewComments).

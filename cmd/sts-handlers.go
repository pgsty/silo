/// Copyright (c) 2015-2021 MinIO, Inc.
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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	idldap "github.com/minio/minio/internal/config/identity/ldap"
	"github.com/minio/minio/internal/config/identity/openid"
	"github.com/minio/minio/internal/hash/sha256"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/mux"
	"github.com/pgsty/silo-pkg/v3/policy"
	"github.com/pgsty/silo-pkg/v3/wildcard"
)

const (
	// STS API version.
	stsAPIVersion             = "2011-06-15"
	stsVersion                = "Version"
	stsAction                 = "Action"
	stsPolicy                 = "Policy"
	stsToken                  = "Token"
	stsRoleArn                = "RoleArn"
	stsWebIdentityToken       = "WebIdentityToken"
	stsWebIdentityAccessToken = "WebIdentityAccessToken" // only valid if UserInfo is enabled.
	stsDurationSeconds        = "DurationSeconds"
	stsLDAPUsername           = "LDAPUsername"
	stsLDAPPassword           = "LDAPPassword"
	stsRevokeTokenType        = "TokenRevokeType"

	// STS API action constants
	clientGrants        = "AssumeRoleWithClientGrants"
	webIdentity         = "AssumeRoleWithWebIdentity"
	ldapIdentity        = "AssumeRoleWithLDAPIdentity"
	clientCertificate   = "AssumeRoleWithCertificate"
	customTokenIdentity = "AssumeRoleWithCustomToken"
	assumeRole          = "AssumeRole"

	stsRequestBodyLimit = 10 * (1 << 20) // 10 MiB

	// JWT claim keys
	expClaim = "exp"
	subClaim = "sub"
	audClaim = "aud"
	issClaim = "iss"

	// JWT claim to check the parent user
	parentClaim = "parent"

	// LDAP claim keys
	ldapUser       = "ldapUser"       // this is a key name for a normalized DN value
	ldapActualUser = "ldapActualUser" // this is a key name for the actual DN value
	ldapUserN      = "ldapUsername"   // this is a key name for the short/login username
	// Claim key-prefix for LDAP attributes
	ldapAttribPrefix = "ldapAttrib_"

	// Role Claim key
	roleArnClaim = "roleArn"

	// STS revoke type claim key
	tokenRevokeTypeClaim = "tokenRevokeType"

	// maximum supported STS session policy size
	maxSTSSessionPolicySize = 2048

	stsLDAPLoginBurst         = 10
	stsLDAPLoginEntryTTL      = 15 * time.Minute
	stsLDAPLoginRetryAfterSec = int((time.Minute / stsLDAPLoginBurst) / time.Second)
)

var (
	// One message for unknown users and wrong passwords. The console tries
	// the built-in login (root, access keys) only when the LDAP error says
	// "not found", so the message keeps those words.
	errLDAPAuthenticationFailed   = errors.New("LDAP authentication failed: user not found or invalid password")
	globalSTSLDAPLoginRateLimiter = newSTSLDAPLoginRateLimiter(time.Minute/time.Duration(stsLDAPLoginBurst), stsLDAPLoginBurst, stsLDAPLoginEntryTTL)
)

type stsClaims map[string]any

func (c stsClaims) populateSessionPolicy(form url.Values) error {
	if len(form) == 0 {
		return nil
	}

	sessionPolicyStr := form.Get(stsPolicy)
	if len(sessionPolicyStr) == 0 {
		return nil
	}

	sessionPolicy, err := policy.ParseConfig(bytes.NewReader([]byte(sessionPolicyStr)))
	if err != nil {
		return err
	}

	// Version in policy must not be empty
	if sessionPolicy.Version == "" {
		return errors.New("Version cannot be empty expecting '2012-10-17'")
	}

	policyBuf, err := json.Marshal(sessionPolicy)
	if err != nil {
		return err
	}

	// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
	// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
	// The plain text that you use for both inline and managed session
	// policies shouldn't exceed maxSTSSessionPolicySize characters.
	if len(policyBuf) > maxSTSSessionPolicySize {
		return errSessionPolicyTooLarge
	}

	c[policy.SessionPolicyName] = base64.StdEncoding.EncodeToString(policyBuf)
	return nil
}

// stsAPIHandlers implements and provides http handlers for AWS STS API.
type stsAPIHandlers struct{}

// registerSTSRouter - registers AWS STS compatible APIs.
func registerSTSRouter(router *mux.Router) {
	// Initialize STS.
	sts := &stsAPIHandlers{}

	// STS Router
	stsRouter := router.NewRoute().PathPrefix(SlashSeparator).Subrouter()

	// Assume roles with no JWT, handles AssumeRole.
	stsRouter.Methods(http.MethodPost).MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		ctypeOk := wildcard.MatchSimple("application/x-www-form-urlencoded*", r.Header.Get(xhttp.ContentType))
		authOk := wildcard.MatchSimple(signV4Algorithm+"*", r.Header.Get(xhttp.Authorization))
		noQueries := len(r.URL.RawQuery) == 0
		return ctypeOk && authOk && noQueries
	}).HandlerFunc(httpTraceAll(sts.AssumeRole))

	// Assume roles with JWT handler, handles both ClientGrants and WebIdentity.
	stsRouter.Methods(http.MethodPost).MatcherFunc(func(r *http.Request, rm *mux.RouteMatch) bool {
		ctypeOk := wildcard.MatchSimple("application/x-www-form-urlencoded*", r.Header.Get(xhttp.ContentType))
		noQueries := len(r.URL.RawQuery) == 0
		return ctypeOk && noQueries
	}).HandlerFunc(httpTraceAll(sts.AssumeRoleWithSSO))

	// AssumeRoleWithClientGrants
	stsRouter.Methods(http.MethodPost).HandlerFunc(httpTraceAll(sts.AssumeRoleWithClientGrants)).
		Queries(stsAction, clientGrants).
		Queries(stsVersion, stsAPIVersion).
		Queries(stsToken, "{Token:.*}")

	// AssumeRoleWithWebIdentity
	stsRouter.Methods(http.MethodPost).HandlerFunc(httpTraceAll(sts.AssumeRoleWithWebIdentity)).
		Queries(stsAction, webIdentity).
		Queries(stsVersion, stsAPIVersion).
		Queries(stsWebIdentityToken, "{Token:.*}")

	// AssumeRoleWithLDAPIdentity
	stsRouter.Methods(http.MethodPost).HandlerFunc(httpTraceAll(sts.AssumeRoleWithLDAPIdentity)).
		Queries(stsAction, ldapIdentity).
		Queries(stsVersion, stsAPIVersion).
		Queries(stsLDAPUsername, "{LDAPUsername:.*}").
		Queries(stsLDAPPassword, "{LDAPPassword:.*}")

	// AssumeRoleWithCertificate
	stsRouter.Methods(http.MethodPost).HandlerFunc(httpTraceAll(sts.AssumeRoleWithCertificate)).
		Queries(stsAction, clientCertificate).
		Queries(stsVersion, stsAPIVersion)

	// AssumeRoleWithCustomToken
	stsRouter.Methods(http.MethodPost).HandlerFunc(httpTraceAll(sts.AssumeRoleWithCustomToken)).
		Queries(stsAction, customTokenIdentity).
		Queries(stsVersion, stsAPIVersion)
}

func apiToSTSError(authErr APIErrorCode) (stsErrCode STSErrorCode) {
	switch authErr {
	case ErrSignatureDoesNotMatch, ErrInvalidAccessKeyID, ErrAccessKeyDisabled:
		return ErrSTSAccessDenied
	case ErrServerNotInitialized:
		return ErrSTSNotInitialized
	case ErrInternalError:
		return ErrSTSInternalError
	default:
		return ErrSTSAccessDenied
	}
}

func checkAssumeRoleAuth(ctx context.Context, r *http.Request) (auth.Credentials, APIErrorCode) {
	if !isRequestSignatureV4(r) {
		return auth.Credentials{}, ErrAccessDenied
	}

	s3Err := isReqAuthenticated(ctx, r, globalSite.Region(), serviceSTS)
	if s3Err != ErrNone {
		return auth.Credentials{}, s3Err
	}

	user, _, s3Err := getReqAccessKeyV4(r, globalSite.Region(), serviceSTS)
	if s3Err != ErrNone {
		return auth.Credentials{}, s3Err
	}

	// Temporary credentials or Service accounts cannot generate further temporary credentials.
	if user.IsTemp() || user.IsServiceAccount() {
		return auth.Credentials{}, ErrAccessDenied
	}

	// Session tokens are not allowed in STS AssumeRole requests.
	if getSessionToken(r) != "" {
		return auth.Credentials{}, ErrAccessDenied
	}

	return user, ErrNone
}

func parseForm(r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	for k, v := range r.PostForm {
		if _, ok := r.Form[k]; !ok {
			r.Form[k] = v
		}
	}
	return nil
}

// getTokenSigningKey returns secret key used to sign JWT session tokens
func getTokenSigningKey() (string, error) {
	secret := globalActiveCred.SecretKey
	if globalSiteReplicationSys.isEnabled() {
		secretKey, err := globalSiteReplicatorCred.Get(GlobalContext)
		if err != nil {
			return "", err
		}
		return secretKey, nil
	}
	return secret, nil
}

// stsLDAPLoginRateLimiter throttles LDAP STS logins per source IP. It does not
// bucket by username on purpose: a username-keyed bucket is shared across all
// sources, so a single client sending bad-password attempts for a known account
// could keep that account's bucket drained and lock the legitimate user out.
//
// Scope of protection: the per-source bucket caps the attempt rate from any one
// source, and the uniform auth-failure response (not this limiter) is what hides
// whether a username exists. It does not stop attackers who spread across many
// sources (botnets, IPv6 address rotation) or the residual bind-timing side
// channel; those are accepted limitations of an in-memory, per-source control.
type stsLDAPLoginRateLimiter struct {
	source *stsLDAPLoginKeyLimiterSet
}

type stsLDAPLoginReservation struct {
	source *stsLDAPLoginKeyReservation
}

type stsLDAPLoginKeyLimiterSet struct {
	mu          sync.Mutex
	refillEvery time.Duration
	burst       int
	ttl         time.Duration
	lastCleanup time.Time
	entries     map[string]*stsLDAPLoginKeyLimiter
}

type stsLDAPLoginKeyLimiter struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
	inFlight   int
}

type stsLDAPLoginKeyReservation struct {
	set       *stsLDAPLoginKeyLimiterSet
	entry     *stsLDAPLoginKeyLimiter
	finalized bool
}

func newSTSLDAPLoginRateLimiter(refillEvery time.Duration, burst int, ttl time.Duration) *stsLDAPLoginRateLimiter {
	return &stsLDAPLoginRateLimiter{
		source: newSTSLDAPLoginKeyLimiterSet(refillEvery, burst, ttl),
	}
}

func newSTSLDAPLoginKeyLimiterSet(refillEvery time.Duration, burst int, ttl time.Duration) *stsLDAPLoginKeyLimiterSet {
	return &stsLDAPLoginKeyLimiterSet{
		refillEvery: refillEvery,
		burst:       burst,
		ttl:         ttl,
		entries:     make(map[string]*stsLDAPLoginKeyLimiter),
	}
}

func (l *stsLDAPLoginRateLimiter) Allow(sourceIP string) bool {
	reservation := l.Reserve(sourceIP)
	if reservation == nil {
		return false
	}
	reservation.Commit()
	return true
}

func (l *stsLDAPLoginRateLimiter) Reserve(sourceIP string) *stsLDAPLoginReservation {
	// An empty source IP means we could not identify the peer; do not throttle
	// rather than collapse every such request into one shared bucket.
	if sourceIP == "" {
		return &stsLDAPLoginReservation{}
	}

	source := l.source.Reserve(UTCNow(), sourceIP)
	if source == nil {
		return nil
	}
	return &stsLDAPLoginReservation{source: source}
}

func (r *stsLDAPLoginReservation) Commit() {
	if r == nil || r.source == nil {
		return
	}
	r.source.CommitAt(UTCNow())
	r.source = nil
}

func (r *stsLDAPLoginReservation) Cancel() {
	if r == nil || r.source == nil {
		return
	}
	r.source.CancelAt(UTCNow())
	r.source = nil
}

func (l *stsLDAPLoginKeyLimiterSet) Allow(now time.Time, key string) bool {
	reservation := l.Reserve(now, key)
	if reservation == nil {
		return false
	}
	reservation.CommitAt(now)
	return true
}

func (l *stsLDAPLoginKeyLimiterSet) Reserve(now time.Time, key string) *stsLDAPLoginKeyReservation {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.lastCleanup.IsZero() || now.Sub(l.lastCleanup) >= l.ttl {
		l.cleanup(now)
		l.lastCleanup = now
	}

	entry := l.getOrCreateLocked(now, key)
	l.refillLocked(now, entry)
	if entry.tokens < 1 {
		entry.lastSeen = now
		return nil
	}

	entry.tokens--
	entry.inFlight++
	entry.lastSeen = now
	return &stsLDAPLoginKeyReservation{set: l, entry: entry}
}

func (l *stsLDAPLoginKeyLimiterSet) cleanup(now time.Time) {
	for key, entry := range l.entries {
		if entry.inFlight == 0 && now.Sub(entry.lastSeen) > l.ttl {
			delete(l.entries, key)
		}
	}
}

func (l *stsLDAPLoginKeyLimiterSet) getOrCreateLocked(now time.Time, key string) *stsLDAPLoginKeyLimiter {
	entry, ok := l.entries[key]
	if !ok {
		entry = &stsLDAPLoginKeyLimiter{
			tokens:     float64(l.burst),
			lastRefill: now,
			lastSeen:   now,
		}
		l.entries[key] = entry
	}
	return entry
}

func (l *stsLDAPLoginKeyLimiterSet) refillLocked(now time.Time, entry *stsLDAPLoginKeyLimiter) {
	if entry.lastRefill.IsZero() {
		entry.lastRefill = now
	}

	lastRefill := entry.lastRefill
	if now.Before(lastRefill) {
		lastRefill = now
	}
	if l.refillEvery <= 0 {
		entry.lastRefill = now
		entry.tokens = l.maxTokensLocked(entry)
		return
	}

	entry.tokens += float64(now.Sub(lastRefill)) / float64(l.refillEvery)
	if maxTokens := l.maxTokensLocked(entry); entry.tokens > maxTokens {
		entry.tokens = maxTokens
	}
	entry.lastRefill = now
}

func (l *stsLDAPLoginKeyLimiterSet) maxTokensLocked(entry *stsLDAPLoginKeyLimiter) float64 {
	maxTokens := l.burst - entry.inFlight
	if maxTokens < 0 {
		return 0
	}
	return float64(maxTokens)
}

func (r *stsLDAPLoginKeyReservation) CommitAt(now time.Time) {
	r.finalize(now, false)
}

func (r *stsLDAPLoginKeyReservation) CancelAt(now time.Time) {
	r.finalize(now, true)
}

func (r *stsLDAPLoginKeyReservation) finalize(now time.Time, refund bool) {
	if r == nil {
		return
	}

	r.set.mu.Lock()
	defer r.set.mu.Unlock()

	if r.finalized {
		return
	}

	r.set.refillLocked(now, r.entry)
	r.entry.lastSeen = now
	if r.entry.inFlight > 0 {
		r.entry.inFlight--
	}
	if refund {
		r.entry.tokens++
		if maxTokens := r.set.maxTokensLocked(r.entry); r.entry.tokens > maxTokens {
			r.entry.tokens = maxTokens
		}
	}

	r.finalized = true
}

func getSTSLDAPLoginSourceIP(r *http.Request) string {
	peerIP := getSTSLDAPLoginCanonicalIP(r.RemoteAddr)
	sourceIP := peerIP
	if sourceIP == "" {
		sourceIP = getSTSLDAPLoginPeerAddr(r.RemoteAddr)
	}
	if peerIP != "" && globalIAMSys != nil && globalIAMSys.LDAPConfig.IsSTSTrustedProxy(peerIP) {
		if forwardedIP := getSTSLDAPTrustedProxySourceIP(r); forwardedIP != "" {
			return forwardedIP
		}
	}
	return sourceIP
}

// getSTSLDAPTrustedProxySourceIP resolves the client IP for a request whose peer
// is an allow-listed trusted proxy. A single clean X-Real-IP is preferred; for
// X-Forwarded-For we walk the chain right-to-left and skip trusted-proxy hops,
// returning the first untrusted address. The XFF result ignores any client-
// supplied (left-most) value unless the entire chain to its right is trusted,
// which an external client cannot forge.
//
// X-Real-IP, unlike XFF, is a single value with no chain, so it cannot be
// validated against the allowlist: it is trusted verbatim. The deployment
// contract is therefore that the trusted proxy MUST overwrite (not pass through)
// any client-supplied X-Real-IP; otherwise an attacker can vary it per request
// to evade per-source throttling. This is the standard reverse-proxy real-IP
// contract; reordering to prefer XFF would not remove the dependency, only move
// it (an X-Real-IP-only proxy would then be evaded via an injected XFF header).
//
// The RFC 7239 Forwarded header is intentionally not honored here; such
// deployments fall back to the safe peer-address bucket.
func getSTSLDAPTrustedProxySourceIP(r *http.Request) string {
	if realIP := getSTSLDAPLoginCanonicalIP(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}

	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		ip := getSTSLDAPLoginCanonicalIP(forwarded[i])
		if ip == "" || globalIAMSys.LDAPConfig.IsSTSTrustedProxy(ip) {
			continue
		}
		return ip
	}
	return ""
}

func getSTSLDAPLoginPeerAddr(remoteAddr string) string {
	sourceIP, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return sourceIP
	}
	return remoteAddr
}

func getSTSLDAPLoginCanonicalIP(addr string) string {
	addr = strings.TrimSpace(getSTSLDAPLoginPeerAddr(addr))
	addr = strings.TrimPrefix(addr, "[")
	addr = strings.TrimSuffix(addr, "]")
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String()
	}
	return ""
}

// reserveSTSLDAPLogin acquires an immediate token from the per-source limiter
// before contacting LDAP. Call Commit on auth failures and Cancel when the
// attempt should not count as an authentication failure.
func reserveSTSLDAPLogin(r *http.Request) *stsLDAPLoginReservation {
	return globalSTSLDAPLoginRateLimiter.Reserve(getSTSLDAPLoginSourceIP(r))
}

func ldapBindErrorToSTS(err error) (STSErrorCode, error) {
	if idldap.IsAuthError(err) {
		return ErrSTSInvalidParameterValue, errLDAPAuthenticationFailed
	}
	return ErrSTSUpstreamError, nil
}

func writeSTSThrottledResponse(w http.ResponseWriter) {
	stsErrorResponse := STSErrorResponse{}
	stsErrorResponse.Error.Code = "ThrottlingException"
	stsErrorResponse.Error.Message = "Request throttled, please retry later."
	stsErrorResponse.RequestID = w.Header().Get(xhttp.AmzRequestID)

	w.Header().Set("Retry-After", strconv.Itoa(stsLDAPLoginRetryAfterSec))

	encodedErrorResponse := encodeResponse(stsErrorResponse)
	writeResponse(w, http.StatusTooManyRequests, encodedErrorResponse, mimeXML)
}

// AssumeRole - implementation of AWS STS API AssumeRole to get temporary
// credentials for regular users on Minio.
// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
func (sts *stsAPIHandlers) AssumeRole(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AssumeRole")

	claims := stsClaims{}
	defer logger.AuditLog(ctx, w, r, claims)

	// Check auth here (otherwise r.Form will have unexpected values from
	// the call to `parseForm` below), but return failure only after we are
	// able to validate that it is a valid STS request, so that we are able
	// to send an appropriate audit log.
	user, apiErrCode := checkAssumeRoleAuth(ctx, r)

	if err := parseForm(r); err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	if r.Form.Get(stsVersion) != stsAPIVersion {
		writeSTSErrorResponse(ctx, w, ErrSTSMissingParameter, fmt.Errorf("Invalid STS API version %s, expecting %s", r.Form.Get(stsVersion), stsAPIVersion))
		return
	}

	action := r.Form.Get(stsAction)
	switch action {
	case assumeRole:
	default:
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, fmt.Errorf("Unsupported action %s", action))
		return
	}

	ctx = newContext(r, w, action)

	// Validate the authentication result here so that failures will be audit-logged.
	if apiErrCode != ErrNone {
		stsErr := apiToSTSError(apiErrCode)
		// Borrow the description error from the API error code
		writeSTSErrorResponse(ctx, w, stsErr, errors.New(errorCodes[apiErrCode].Description))
		return
	}

	if err := claims.populateSessionPolicy(r.Form); err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	duration, err := openid.GetDefaultExpiration(r.Form.Get(stsDurationSeconds))
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	claims[expClaim] = UTCNow().Add(duration).Unix()
	claims[parentClaim] = user.AccessKey
	if err := setIAMParentRevocationClaim(ctx, globalIAMSys.store, user.AccessKey, claims); err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	tokenRevokeType := r.Form.Get(stsRevokeTokenType)
	if tokenRevokeType != "" {
		claims[tokenRevokeTypeClaim] = tokenRevokeType
	}

	// Validate that user.AccessKey's policies can be retrieved - it may not
	// be in case the user is disabled.
	if _, err = globalIAMSys.PolicyDBGet(user.AccessKey, user.Groups...); err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	secret, err := getTokenSigningKey()
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	cred, err := auth.GetNewCredentialsWithMetadata(claims, secret)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	// Set the parent of the temporary access key, so that it's access
	// policy is inherited from `user.AccessKey`.
	cred.ParentUser = user.AccessKey

	// Set the newly generated credentials.
	updatedAt, err := globalIAMSys.SetTempUser(ctx, cred.AccessKey, cred, "")
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	// Call hook for site replication.
	if cred.ParentUser != globalActiveCred.AccessKey {
		replLogIf(ctx, globalSiteReplicationSys.IAMChangeHook(ctx, madmin.SRIAMItem{
			Type: madmin.SRIAMItemSTSAcc,
			STSCredential: &madmin.SRSTSCredential{
				AccessKey:    cred.AccessKey,
				SecretKey:    cred.SecretKey,
				SessionToken: cred.SessionToken,
				ParentUser:   cred.ParentUser,
			},
			UpdatedAt: updatedAt,
		}))
	}

	assumeRoleResponse := &AssumeRoleResponse{
		Result: AssumeRoleResult{
			Credentials: cred,
		},
	}

	assumeRoleResponse.ResponseMetadata.RequestID = w.Header().Get(xhttp.AmzRequestID)
	writeSuccessResponseXML(w, encodeResponse(assumeRoleResponse))
}

func (sts *stsAPIHandlers) AssumeRoleWithSSO(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AssumeRoleSSOCommon")

	claims := stsClaims{}
	defer logger.AuditLog(ctx, w, r, claims)

	// Parse the incoming form data.
	if err := parseForm(r); err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	if r.Form.Get(stsVersion) != stsAPIVersion {
		writeSTSErrorResponse(ctx, w, ErrSTSMissingParameter, fmt.Errorf("Invalid STS API version %s, expecting %s", r.Form.Get("Version"), stsAPIVersion))
		return
	}

	action := r.Form.Get(stsAction)
	switch action {
	case ldapIdentity:
		sts.AssumeRoleWithLDAPIdentity(w, r)
		return
	case clientGrants, webIdentity:
	default:
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, fmt.Errorf("Unsupported action %s", action))
		return
	}

	ctx = newContext(r, w, action)

	token := r.Form.Get(stsToken)
	if token == "" {
		token = r.Form.Get(stsWebIdentityToken)
	}

	accessToken := r.Form.Get(stsWebIdentityAccessToken)

	// RoleARN parameter processing: If a role ARN is given in the request, we
	// use that and validate the authentication request. If not, we assume this
	// is an STS request for a claim based IDP (if one is present) and set
	// roleArn = openid.DummyRoleARN.
	//
	// Currently, we do not support multiple claim based IDPs, as there is no
	// defined parameter to disambiguate the intended IDP in this STS request.
	roleArn := openid.DummyRoleARN
	roleArnStr := r.Form.Get(stsRoleArn)
	isRolePolicyProvider := roleArnStr != ""
	if isRolePolicyProvider {
		var err error
		roleArn, _, err = globalIAMSys.GetRolePolicy(roleArnStr)
		if err != nil {
			// If there is no claim-based provider configured, then an
			// unrecognized roleArn is an error
			if strings.TrimSpace(iamPolicyClaimNameOpenID()) == "" {
				writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
					fmt.Errorf("Error processing %s parameter: %v", stsRoleArn, err))
				return
			}
			// If there *is* a claim-based provider configured, then
			// treat an unrecognized roleArn the same as no roleArn
			// at all.  This is to support clients like the AWS SDKs
			// or CLI that will not allow an AssumeRoleWithWebIdentity
			// call without a RoleARN parameter - for these cases the
			// user can supply a dummy ARN, which Minio will ignore.
			roleArn = openid.DummyRoleARN
			isRolePolicyProvider = false
		}
	}

	if !globalIAMSys.Initialized() {
		writeSTSErrorResponse(ctx, w, ErrSTSIAMNotInitialized, errIAMNotInitialized)
		return
	}

	// Validate JWT; check clientID in claims matches the one associated with the roleArn
	if err := globalIAMSys.OpenIDConfig.Validate(r.Context(), roleArn, token, accessToken, r.Form.Get(stsDurationSeconds), claims); err != nil {
		switch err {
		case openid.ErrTokenExpired:
			switch action {
			case clientGrants:
				writeSTSErrorResponse(ctx, w, ErrSTSClientGrantsExpiredToken, err)
			case webIdentity:
				writeSTSErrorResponse(ctx, w, ErrSTSWebIdentityExpiredToken, err)
			}
			return
		case auth.ErrInvalidDuration:
			writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
			return
		}
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	var policyName string
	if isRolePolicyProvider {
		// If roleArn is used, we set it as a claim, and use the
		// associated policy when credentials are used.
		claims[roleArnClaim] = roleArn.String()
	} else {
		// If no role policy is configured, then we use claims from the
		// JWT. This is a MinIO STS API specific value, this value
		// should be set and configured on your identity provider as
		// part of JWT custom claims.
		policySet, ok := policy.GetPoliciesFromClaims(claims, iamPolicyClaimNameOpenID())
		policies := strings.Join(policySet.ToSlice(), ",")
		if ok {
			current, err := globalIAMSys.CurrentPolicies(policies)
			if err != nil {
				writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
				return
			}
			policyName = current
		}

		if newGlobalAuthZPluginFn() == nil {
			if !ok {
				writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
					fmt.Errorf("%s claim missing from the JWT token, credentials will not be generated", iamPolicyClaimNameOpenID()))
				return
			} else if policyName == "" {
				writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
					fmt.Errorf("None of the given policies (`%s`) are defined, credentials will not be generated", policies))
				return
			}
		}
		claims[iamPolicyClaimNameOpenID()] = policyName
	}

	tokenRevokeType := r.Form.Get(stsRevokeTokenType)
	if tokenRevokeType != "" {
		claims[tokenRevokeTypeClaim] = tokenRevokeType
	}

	if err := claims.populateSessionPolicy(r.Form); err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	secret, err := getTokenSigningKey()
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}
	cred, err := auth.GetNewCredentialsWithMetadata(claims, secret)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	// https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability
	// claim is only considered stable when subject and iss are used together
	// this is to ensure that ParentUser doesn't change and we get to use
	// parentUser as per the requirements for service accounts for OpenID
	// based logins.
	var subFromToken string
	if v, ok := claims[subClaim]; ok {
		subFromToken, _ = v.(string)
	}

	if subFromToken == "" {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
			errors.New("STS JWT Token has `sub` claim missing, `sub` claim is mandatory"))
		return
	}

	var issFromToken string
	if v, ok := claims[issClaim]; ok {
		issFromToken, _ = v.(string)
	}

	// Since issFromToken can have `/` characters (it is typically the
	// provider URL), we hash and encode it to base64 here. This is needed
	// because there will be a policy mapping stored on drives whose
	// filename is this parentUser: therefore, it needs to have only valid
	// filename characters and needs to have bounded length.
	{
		h := sha256.New()
		h.Write([]byte("openid:" + subFromToken + ":" + issFromToken))
		bs := h.Sum(nil)
		cred.ParentUser = base64.RawURLEncoding.EncodeToString(bs)
	}

	// Deny this assume role request if the policy that the user intends to bind
	// has a sts:DurationSeconds condition, which is not satisfied as well
	{
		p := policyName
		if p == "" {
			var err error
			_, p, err = globalIAMSys.GetRolePolicy(roleArnStr)
			if err != nil {
				writeSTSErrorResponse(ctx, w, ErrSTSAccessDenied, err)
				return
			}
			if newGlobalAuthZPluginFn() == nil {
				// if authZ is not set - we expect the policies to be present.
				current, err := globalIAMSys.CurrentPolicies(p)
				if err != nil {
					writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
					return
				}
				if current == "" {
					writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
						fmt.Errorf("None of the given policies (`%s`) are defined, credentials will not be generated", p))
					return
				}
			}
		}

		if !globalIAMSys.doesPolicyAllow(p, policy.Args{
			DenyOnly:        true,
			Action:          policy.AssumeRoleWithWebIdentityAction,
			ConditionValues: getSTSConditionValues(r, "", cred),
			Claims:          cred.Claims,
		}) {
			writeSTSErrorResponse(ctx, w, ErrSTSAccessDenied, errors.New("this user does not have enough permission"))
			return
		}
	}

	// Set the newly generated credentials.
	updatedAt, err := globalIAMSys.SetTempUser(ctx, cred.AccessKey, cred, policyName)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	// Call hook for site replication.
	replLogIf(ctx, globalSiteReplicationSys.IAMChangeHook(ctx, madmin.SRIAMItem{
		Type: madmin.SRIAMItemSTSAcc,
		STSCredential: &madmin.SRSTSCredential{
			AccessKey:           cred.AccessKey,
			SecretKey:           cred.SecretKey,
			SessionToken:        cred.SessionToken,
			ParentUser:          cred.ParentUser,
			ParentPolicyMapping: policyName,
		},
		UpdatedAt: updatedAt,
	}))

	var encodedSuccessResponse []byte
	switch action {
	case clientGrants:
		clientGrantsResponse := &AssumeRoleWithClientGrantsResponse{
			Result: ClientGrantsResult{
				Credentials:      cred,
				SubjectFromToken: subFromToken,
			},
		}
		clientGrantsResponse.ResponseMetadata.RequestID = w.Header().Get(xhttp.AmzRequestID)
		encodedSuccessResponse = encodeResponse(clientGrantsResponse)
	case webIdentity:
		webIdentityResponse := &AssumeRoleWithWebIdentityResponse{
			Result: WebIdentityResult{
				Credentials:                 cred,
				SubjectFromWebIdentityToken: subFromToken,
			},
		}
		webIdentityResponse.ResponseMetadata.RequestID = w.Header().Get(xhttp.AmzRequestID)
		encodedSuccessResponse = encodeResponse(webIdentityResponse)
	}

	writeSuccessResponseXML(w, encodedSuccessResponse)
}

// AssumeRoleWithWebIdentity - implementation of AWS STS API supporting OAuth2.0
// users from web identity provider such as Facebook, Google, or any OpenID
// Connect-compatible identity provider.
//
// Eg:-
//
//	$ curl https://minio:9000/?Action=AssumeRoleWithWebIdentity&WebIdentityToken=<jwt>
func (sts *stsAPIHandlers) AssumeRoleWithWebIdentity(w http.ResponseWriter, r *http.Request) {
	sts.AssumeRoleWithSSO(w, r)
}

// AssumeRoleWithClientGrants - implementation of AWS STS extension API supporting
// OAuth2.0 client credential grants.
//
// Eg:-
//
//	$ curl https://minio:9000/?Action=AssumeRoleWithClientGrants&Token=<jwt>
func (sts *stsAPIHandlers) AssumeRoleWithClientGrants(w http.ResponseWriter, r *http.Request) {
	sts.AssumeRoleWithSSO(w, r)
}

// AssumeRoleWithLDAPIdentity - implements user auth against LDAP server
func (sts *stsAPIHandlers) AssumeRoleWithLDAPIdentity(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AssumeRoleWithLDAPIdentity")

	claims := stsClaims{}
	defer logger.AuditLog(ctx, w, r, claims, stsLDAPPassword)

	// Parse the incoming form data.
	if err := parseForm(r); err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	if r.Form.Get(stsVersion) != stsAPIVersion {
		writeSTSErrorResponse(ctx, w, ErrSTSMissingParameter,
			fmt.Errorf("Invalid STS API version %s, expecting %s", r.Form.Get("Version"), stsAPIVersion))
		return
	}

	ldapUsername := r.Form.Get(stsLDAPUsername)
	ldapPassword := r.Form.Get(stsLDAPPassword)

	if ldapUsername == "" || ldapPassword == "" {
		writeSTSErrorResponse(ctx, w, ErrSTSMissingParameter, fmt.Errorf("LDAPUsername and LDAPPassword cannot be empty"))
		return
	}

	action := r.Form.Get(stsAction)
	switch action {
	case ldapIdentity:
	default:
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, fmt.Errorf("Unsupported action %s", action))
		return
	}

	if err := claims.populateSessionPolicy(r.Form); err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	if !globalIAMSys.Initialized() {
		writeSTSErrorResponse(ctx, w, ErrSTSIAMNotInitialized, errIAMNotInitialized)
		return
	}

	loginReservation := reserveSTSLDAPLogin(r)
	if loginReservation == nil {
		writeSTSThrottledResponse(w)
		return
	}
	defer loginReservation.Cancel()

	lookupResult, groupDistNames, err := globalIAMSys.LDAPConfig.Bind(ldapUsername, ldapPassword)
	if err != nil {
		errCode, errResp := ldapBindErrorToSTS(err)
		if errCode == ErrSTSUpstreamError {
			loginReservation.Cancel()
			stsLogIf(ctx, err, logger.ErrorKind)
		} else {
			loginReservation.Commit()
		}
		writeSTSErrorResponse(ctx, w, errCode, errResp)
		return
	}
	loginReservation.Cancel()
	ldapUserDN := lookupResult.NormDN
	ldapActualUserDN := lookupResult.ActualDN

	// Check if this user or their groups have a policy applied.
	ldapPolicies, err := globalIAMSys.PolicyDBGet(ldapUserDN, groupDistNames...)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}
	if len(ldapPolicies) == 0 && newGlobalAuthZPluginFn() == nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
			fmt.Errorf("expecting a policy to be set for user `%s` or one of their groups: `%s` - rejecting this request",
				ldapActualUserDN, strings.Join(groupDistNames, "`,`")))
		return
	}

	expiryDur, err := globalIAMSys.LDAPConfig.GetExpiryDuration(r.Form.Get(stsDurationSeconds))
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	claims[expClaim] = UTCNow().Add(expiryDur).Unix()
	claims[ldapUser] = ldapUserDN
	claims[ldapActualUser] = ldapActualUserDN
	claims[ldapUserN] = ldapUsername
	// Add lookup up LDAP attributes as claims.
	for attrib, value := range lookupResult.Attributes {
		claims[ldapAttribPrefix+attrib] = value
	}
	tokenRevokeType := r.Form.Get(stsRevokeTokenType)
	if tokenRevokeType != "" {
		claims[tokenRevokeTypeClaim] = tokenRevokeType
	}

	secret, err := getTokenSigningKey()
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	cred, err := auth.GetNewCredentialsWithMetadata(claims, secret)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	// Set the parent of the temporary access key, this is useful
	// in obtaining service accounts by this cred.
	cred.ParentUser = ldapUserDN

	// Set this value to LDAP groups, LDAP user can be part
	// of large number of groups
	cred.Groups = groupDistNames

	// Set the newly generated credentials, policyName is empty on purpose
	// LDAP policies are applied automatically using their ldapUser, ldapGroups
	// mapping.
	updatedAt, err := globalIAMSys.SetTempUser(ctx, cred.AccessKey, cred, "")
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	// Call hook for site replication.
	replLogIf(ctx, globalSiteReplicationSys.IAMChangeHook(ctx, madmin.SRIAMItem{
		Type: madmin.SRIAMItemSTSAcc,
		STSCredential: &madmin.SRSTSCredential{
			AccessKey:    cred.AccessKey,
			SecretKey:    cred.SecretKey,
			SessionToken: cred.SessionToken,
			ParentUser:   cred.ParentUser,
		},
		UpdatedAt: updatedAt,
	}))

	ldapIdentityResponse := &AssumeRoleWithLDAPResponse{
		Result: LDAPIdentityResult{
			Credentials: cred,
		},
	}
	ldapIdentityResponse.ResponseMetadata.RequestID = w.Header().Get(xhttp.AmzRequestID)
	encodedSuccessResponse := encodeResponse(ldapIdentityResponse)

	writeSuccessResponseXML(w, encodedSuccessResponse)
}

// AssumeRoleWithCertificate implements user authentication with client certificates.
// It verifies the client-provided X.509 certificate, maps the certificate to an S3 policy
// and returns temp. S3 credentials to the client.
//
// API endpoint: https://minio:9000?Action=AssumeRoleWithCertificate&Version=2011-06-15
func (sts *stsAPIHandlers) AssumeRoleWithCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AssumeRoleWithCertificate")

	claims := make(map[string]any)
	defer logger.AuditLog(ctx, w, r, claims)

	if !globalIAMSys.Initialized() {
		writeSTSErrorResponse(ctx, w, ErrSTSIAMNotInitialized, errIAMNotInitialized)
		return
	}

	if !globalIAMSys.STSTLSConfig.Enabled {
		writeSTSErrorResponse(ctx, w, ErrSTSNotInitialized, errors.New("STS API 'AssumeRoleWithCertificate' is disabled"))
		return
	}

	// We have to establish a TLS connection and the
	// client must provide exactly one client certificate.
	// Otherwise, we don't have a certificate to verify or
	// the policy lookup would ambiguous.
	if r.TLS == nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInsecureConnection, errors.New("No TLS connection attempt"))
		return
	}

	// A client may send a certificate chain such that we end up
	// with multiple peer certificates. However, we can only accept
	// a single client certificate. Otherwise, the certificate to
	// policy mapping would be ambiguous.
	// However, we can filter all CA certificates and only check
	// whether they client has sent exactly one (non-CA) leaf certificate.
	const MaxIntermediateCAs = 10
	var (
		peerCertificates = make([]*x509.Certificate, 0, len(r.TLS.PeerCertificates))
		intermediates    *x509.CertPool
		numIntermediates int
	)
	for _, cert := range r.TLS.PeerCertificates {
		if cert.IsCA {
			numIntermediates++
			if numIntermediates > MaxIntermediateCAs {
				writeSTSErrorResponse(ctx, w, ErrSTSTooManyIntermediateCAs, fmt.Errorf("client certificate contains more than %d intermediate CAs", MaxIntermediateCAs))
				return
			}
			if intermediates == nil {
				intermediates = x509.NewCertPool()
			}
			intermediates.AddCert(cert)
		} else {
			peerCertificates = append(peerCertificates, cert)
		}
	}
	r.TLS.PeerCertificates = peerCertificates

	// Now, we have to check that the client has provided exactly one leaf
	// certificate that we can map to a policy.
	if len(r.TLS.PeerCertificates) == 0 {
		writeSTSErrorResponse(ctx, w, ErrSTSMissingParameter, errors.New("No client certificate provided"))
		return
	}
	if len(r.TLS.PeerCertificates) > 1 {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, errors.New("More than one client certificate provided"))
		return
	}

	certificate := r.TLS.PeerCertificates[0]
	if !globalIAMSys.STSTLSConfig.InsecureSkipVerify { // Verify whether the client certificate has been issued by a trusted CA.
		_, err := certificate.Verify(x509.VerifyOptions{
			KeyUsages: []x509.ExtKeyUsage{
				x509.ExtKeyUsageClientAuth,
			},
			Intermediates: intermediates,
			Roots:         globalRootCAs,
		})
		if err != nil {
			writeSTSErrorResponse(ctx, w, ErrSTSInvalidClientCertificate, err)
			return
		}
	} else {
		// Technically, there is no security argument for verifying the key usage
		// when we don't verify that the certificate has been issued by a trusted CA.
		// Any client can create a certificate with arbitrary key usage settings.
		//
		// However, this check ensures that a certificate with an invalid key usage
		// gets rejected even when we skip certificate verification. This helps
		// clients detect malformed certificates during testing instead of e.g.
		// a self-signed certificate that works while a comparable certificate
		// issued by a trusted CA fails due to the MinIO server being less strict
		// w.r.t. key usage verification.
		//
		// Basically, MinIO is more consistent (from a client perspective) when
		// we verify the key usage all the time.
		var validKeyUsage bool
		for _, usage := range certificate.ExtKeyUsage {
			if usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageClientAuth {
				validKeyUsage = true
				break
			}
		}
		if !validKeyUsage {
			writeSTSErrorResponse(ctx, w, ErrSTSMissingParameter, errors.New("certificate is not valid for client authentication"))
			return
		}
	}

	// We map the X.509 subject common name to the policy. So, a client
	// with the common name "foo" will be associated with the policy "foo".
	// Other mapping functions - e.g. public-key hash based mapping - are
	// possible but not implemented.
	//
	// Group mapping is not possible with standard X.509 certificates.
	if certificate.Subject.CommonName == "" {
		writeSTSErrorResponse(ctx, w, ErrSTSMissingParameter, errors.New("certificate subject CN cannot be empty"))
		return
	}

	expiry, err := globalIAMSys.STSTLSConfig.GetExpiryDuration(r.Form.Get(stsDurationSeconds))
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSMissingParameter, err)
		return
	}

	// We set the expiry of the temp. credentials to the minimum of the
	// configured expiry and the duration until the certificate itself
	// expires.
	// We must not issue credentials that out-live the certificate.
	if validUntil := time.Until(certificate.NotAfter); validUntil < expiry {
		expiry = validUntil
	}

	// Associate any service accounts to the certificate CN
	parentUser := "tls" + getKeySeparator() + certificate.Subject.CommonName

	claims[expClaim] = UTCNow().Add(expiry).Unix()
	claims[subClaim] = certificate.Subject.CommonName
	claims[audClaim] = certificate.Subject.Organization
	claims[issClaim] = certificate.Issuer.CommonName
	claims[parentClaim] = parentUser
	tokenRevokeType := r.Form.Get(stsRevokeTokenType)
	if tokenRevokeType != "" {
		claims[tokenRevokeTypeClaim] = tokenRevokeType
	}

	secretKey, err := getTokenSigningKey()
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}
	tmpCredentials, err := auth.GetNewCredentialsWithMetadata(claims, secretKey)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	tmpCredentials.ParentUser = parentUser
	policyName := certificate.Subject.CommonName
	updatedAt, err := globalIAMSys.SetTempUser(ctx, tmpCredentials.AccessKey, tmpCredentials, policyName)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	// Call hook for site replication.
	replLogIf(ctx, globalSiteReplicationSys.IAMChangeHook(ctx, madmin.SRIAMItem{
		Type: madmin.SRIAMItemSTSAcc,
		STSCredential: &madmin.SRSTSCredential{
			AccessKey:           tmpCredentials.AccessKey,
			SecretKey:           tmpCredentials.SecretKey,
			SessionToken:        tmpCredentials.SessionToken,
			ParentUser:          tmpCredentials.ParentUser,
			ParentPolicyMapping: policyName,
		},
		UpdatedAt: updatedAt,
	}))

	response := new(AssumeRoleWithCertificateResponse)
	response.Result.Credentials = tmpCredentials
	response.Metadata.RequestID = w.Header().Get(xhttp.AmzRequestID)
	writeSuccessResponseXML(w, encodeResponse(response))
}

// AssumeRoleWithCustomToken implements user authentication with custom tokens.
// These tokens are opaque to MinIO and are verified by a configured (external)
// Identity Management Plugin.
//
// API endpoint: https://minio:9000?Action=AssumeRoleWithCustomToken&Token=xxx
func (sts *stsAPIHandlers) AssumeRoleWithCustomToken(w http.ResponseWriter, r *http.Request) {
	ctx := newContext(r, w, "AssumeRoleWithCustomToken")

	claims := make(map[string]any)

	auditLogFilterKeys := []string{stsToken}
	defer logger.AuditLog(ctx, w, r, claims, auditLogFilterKeys...)

	if !globalIAMSys.Initialized() {
		writeSTSErrorResponse(ctx, w, ErrSTSIAMNotInitialized, errIAMNotInitialized)
		return
	}

	authn := newGlobalAuthNPluginFn()
	if authn == nil {
		writeSTSErrorResponse(ctx, w, ErrSTSNotInitialized, errors.New("STS API 'AssumeRoleWithCustomToken' is disabled"))
		return
	}

	action := r.Form.Get(stsAction)
	if action != customTokenIdentity {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, fmt.Errorf("Unsupported action %s", action))
		return
	}

	token := r.Form.Get(stsToken)
	if token == "" {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, fmt.Errorf("Invalid empty `Token` parameter provided"))
		return
	}

	durationParam := r.Form.Get(stsDurationSeconds)
	var requestedDuration int
	if durationParam != "" {
		var err error
		requestedDuration, err = strconv.Atoi(durationParam)
		if err != nil {
			writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, fmt.Errorf("Invalid requested duration: %s", durationParam))
			return
		}
	}

	roleArnStr := r.Form.Get(stsRoleArn)
	roleArn, _, err := globalIAMSys.GetRolePolicy(roleArnStr)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
			fmt.Errorf("Error processing parameter %s: %v", stsRoleArn, err))
		return
	}

	_, policyName, err := globalIAMSys.GetRolePolicy(roleArnStr)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSAccessDenied, err)
		return
	}

	if newGlobalAuthZPluginFn() == nil { // if authZ is not set - we expect the policyname to be present.
		current, err := globalIAMSys.CurrentPolicies(policyName)
		if err != nil {
			writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
			return
		}
		if current == "" {
			writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue,
				fmt.Errorf("None of the given policies (`%s`) are defined, credentials will not be generated", policyName))
			return
		}
	}

	res, err := authn.Authenticate(roleArn, token)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInvalidParameterValue, err)
		return
	}

	// If authentication failed, return the error message to the user.
	if res.Failure != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSUpstreamError, errors.New(res.Failure.Reason))
		return
	}

	// It is required that parent user be set.
	if res.Success.User == "" {
		writeSTSErrorResponse(ctx, w, ErrSTSUpstreamError, errors.New("A valid user was not returned by the authenticator."))
		return
	}

	// Expiry is set as minimum of requested value and value allowed by auth
	// plugin.
	expiry := res.Success.MaxValiditySeconds
	if durationParam != "" && requestedDuration < expiry {
		expiry = requestedDuration
	}

	parentUser := "custom" + getKeySeparator() + res.Success.User

	// metadata map
	claims[expClaim] = UTCNow().Add(time.Duration(expiry) * time.Second).Unix()
	claims[subClaim] = parentUser
	claims[roleArnClaim] = roleArn.String()
	claims[parentClaim] = parentUser
	tokenRevokeType := r.Form.Get(stsRevokeTokenType)
	if tokenRevokeType != "" {
		claims[tokenRevokeTypeClaim] = tokenRevokeType
	}

	// Add all other claims from the plugin **without** replacing any
	// existing claims.
	for k, v := range res.Success.Claims {
		if _, ok := claims[k]; !ok {
			claims[k] = v
		}
	}
	secretKey, err := getTokenSigningKey()
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}
	tmpCredentials, err := auth.GetNewCredentialsWithMetadata(claims, secretKey)
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	tmpCredentials.ParentUser = parentUser
	updatedAt, err := globalIAMSys.SetTempUser(ctx, tmpCredentials.AccessKey, tmpCredentials, "")
	if err != nil {
		writeSTSErrorResponse(ctx, w, ErrSTSInternalError, err)
		return
	}

	// Call hook for site replication.
	replLogIf(ctx, globalSiteReplicationSys.IAMChangeHook(ctx, madmin.SRIAMItem{
		Type: madmin.SRIAMItemSTSAcc,
		STSCredential: &madmin.SRSTSCredential{
			AccessKey:    tmpCredentials.AccessKey,
			SecretKey:    tmpCredentials.SecretKey,
			SessionToken: tmpCredentials.SessionToken,
			ParentUser:   tmpCredentials.ParentUser,
		},
		UpdatedAt: updatedAt,
	}))

	response := new(AssumeRoleWithCustomTokenResponse)
	response.Result.Credentials = tmpCredentials
	response.Result.AssumedUser = parentUser
	response.Metadata.RequestID = w.Header().Get(xhttp.AmzRequestID)
	writeSuccessResponseXML(w, encodeResponse(response))
}

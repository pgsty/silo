{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "silo.name" -}}
  {{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "silo.fullname" -}}
  {{- if .Values.fullnameOverride -}}
    {{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
  {{- else -}}
    {{- $name := default .Chart.Name .Values.nameOverride -}}
    {{- if contains $name .Release.Name -}}
      {{- .Release.Name | trunc 63 | trimSuffix "-" -}}
    {{- else -}}
      {{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
    {{- end -}}
  {{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "silo.chart" -}}
  {{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for networkpolicy.
*/}}
{{- define "silo.networkPolicy.apiVersion" -}}
  {{- if semverCompare ">=1.4-0, <1.7-0" .Capabilities.KubeVersion.Version -}}
    {{- print "extensions/v1beta1" -}}
  {{- else if semverCompare ">=1.7-0, <1.16-0" .Capabilities.KubeVersion.Version -}}
    {{- print "networking.k8s.io/v1beta1" -}}
  {{- else if semverCompare "^1.16-0" .Capabilities.KubeVersion.Version -}}
    {{- print "networking.k8s.io/v1" -}}
  {{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for deployment.
*/}}
{{- define "silo.deployment.apiVersion" -}}
  {{- if semverCompare "<1.9-0" .Capabilities.KubeVersion.Version -}}
    {{- print "apps/v1beta2" -}}
  {{- else -}}
    {{- print "apps/v1" -}}
  {{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for statefulset.
*/}}
{{- define "silo.statefulset.apiVersion" -}}
  {{- if semverCompare "<1.16-0" .Capabilities.KubeVersion.Version -}}
    {{- print "apps/v1beta2" -}}
  {{- else -}}
    {{- print "apps/v1" -}}
  {{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for ingress.
*/}}
{{- define "silo.ingress.apiVersion" -}}
  {{- if semverCompare "<1.14-0" .Capabilities.KubeVersion.GitVersion -}}
    {{- print "extensions/v1beta1" -}}
  {{- else if semverCompare "<1.19-0" .Capabilities.KubeVersion.GitVersion -}}
    {{- print "networking.k8s.io/v1beta1" -}}
  {{- else -}}
    {{- print "networking.k8s.io/v1" -}}
  {{- end -}}
{{- end -}}

{{/*
Return the appropriate apiVersion for console ingress.
*/}}
{{- define "silo.consoleIngress.apiVersion" -}}
  {{- if semverCompare "<1.14-0" .Capabilities.KubeVersion.GitVersion -}}
    {{- print "extensions/v1beta1" -}}
  {{- else if semverCompare "<1.19-0" .Capabilities.KubeVersion.GitVersion -}}
    {{- print "networking.k8s.io/v1beta1" -}}
  {{- else -}}
    {{- print "networking.k8s.io/v1" -}}
  {{- end -}}
{{- end -}}

{{/*
Determine secret name.
*/}}
{{- define "silo.secretName" -}}
  {{- if .Values.existingSecret -}}
    {{- .Values.existingSecret }}
  {{- else -}}
    {{- include "silo.fullname" . -}}
  {{- end -}}
{{- end -}}

{{/*
Determine name for scc role and rolebinding
*/}}
{{- define "silo.sccRoleName" -}}
  {{- printf "%s-%s" "scc" (include "silo.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Properly format optional additional arguments to Silo binary
*/}}
{{- define "silo.extraArgs" -}}
{{- range .Values.extraArgs -}}
{{ " " }}{{ . }}
{{- end -}}
{{- end -}}

{{- define "silo.imagePullSecrets" -}}
{{- with (or (.Values.global | default dict).imagePullSecrets .Values.imagePullSecrets) }}
imagePullSecrets: {{- tpl (toYaml .) $ | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Keep the class already chosen for an existing claim when a parent supplies a default. */}}
{{- define "silo.storageClass" -}}
{{- $class := or .Values.persistence.storageClass (.Values.global | default dict).storageClass -}}
{{- if $class -}}
  {{- $spec := dict "storageClassName" (ternary "" $class (eq $class "-")) -}}
  {{- if and .Release.IsUpgrade (not .Values.persistence.storageClass) -}}
    {{- $name := include "silo.fullname" . -}}
    {{- if eq .Values.mode "standalone" -}}
      {{- with (lookup "v1" "PersistentVolumeClaim" .Release.Namespace $name) -}}
        {{- $spec = .spec -}}
      {{- end -}}
    {{- else -}}
      {{- with (lookup "apps/v1" "StatefulSet" .Release.Namespace $name) -}}
        {{- with .spec.volumeClaimTemplates -}}
          {{- $spec = (first .).spec -}}
        {{- end -}}
      {{- end -}}
    {{- end -}}
  {{- end -}}
  {{- if hasKey $spec "storageClassName" -}}
storageClassName: {{ $spec.storageClassName | quote }}
  {{- end -}}
{{- end -}}
{{- end -}}

{{/*
Formats volumeMount for Silo TLS keys and trusted certs
*/}}
{{- define "silo.tlsKeysVolumeMount" -}}
{{- if .Values.tls.enabled }}
- name: cert-secret-volume
  mountPath: {{ .Values.certsPath }}
{{- end }}
{{- if or .Values.tls.enabled (ne .Values.trustedCertsSecret "") }}
{{- $casPath := printf "%s/CAs" .Values.certsPath | clean }}
- name: trusted-cert-secret-volume
  mountPath: {{ $casPath }}
{{- end }}
{{- end -}}

{{/*
Formats volume for Silo TLS keys and trusted certs
*/}}
{{- define "silo.tlsKeysVolume" -}}
{{- if .Values.tls.enabled }}
- name: cert-secret-volume
  secret:
    secretName: {{ tpl .Values.tls.certSecret $ }}
    items:
    - key: {{ .Values.tls.publicCrt }}
      path: public.crt
    - key: {{ .Values.tls.privateKey }}
      path: private.key
{{- end }}
{{- if or .Values.tls.enabled (ne .Values.trustedCertsSecret "") }}
{{- $certSecret := eq .Values.trustedCertsSecret "" | ternary .Values.tls.certSecret .Values.trustedCertsSecret }}
{{- $publicCrt := eq .Values.trustedCertsSecret "" | ternary .Values.tls.publicCrt "" }}
- name: trusted-cert-secret-volume
  secret:
    secretName: {{ $certSecret }}
    {{- if ne $publicCrt "" }}
    items:
    - key: {{ $publicCrt }}
      path: public.crt
    {{- end }}
{{- end }}
{{- end -}}

{{/*
Returns the available value for certain key in an existing secret (if it exists),
otherwise it generates a random value.
*/}}
{{- define "silo.getValueFromSecret" }}
  {{- $len := (default 16 .Length) | int -}}
  {{- $obj := (lookup "v1" "Secret" .Namespace .Name).data -}}
  {{- if $obj }}
    {{- index $obj .Key | b64dec -}}
  {{- else -}}
    {{- randAlphaNum $len -}}
  {{- end -}}
{{- end }}

{{- define "silo.root.username" -}}
  {{- if .Values.rootUser }}
    {{- if .Values.tplRootCredentials }}
      {{- tpl (.Values.rootUser | toString) . }}
    {{- else }}
      {{- .Values.rootUser | toString }}
    {{- end }}
  {{- else }}
    {{- include "silo.getValueFromSecret" (dict "Namespace" .Release.Namespace "Name" (include "silo.fullname" .) "Length" 20 "Key" "rootUser") }}
  {{- end }}
{{- end -}}

{{- define "silo.root.password" -}}
  {{- if .Values.rootPassword }}
    {{- if .Values.tplRootCredentials }}
      {{- tpl (.Values.rootPassword | toString) . }}
    {{- else }}
      {{- .Values.rootPassword | toString }}
    {{- end }}
  {{- else }}
    {{- include "silo.getValueFromSecret" (dict "Namespace" .Release.Namespace "Name" (include "silo.fullname" .) "Length" 40 "Key" "rootPassword") }}
  {{- end }}
{{- end -}}

{{/* OIDC environment shared by the standalone and distributed workloads. */}}
{{- define "silo.oidcEnv" -}}
{{- $oidc := .Values.oidc -}}
{{- if $oidc.enabled -}}
- name: MINIO_IDENTITY_OPENID_CONFIG_URL
  {{- if and $oidc.existingConfigMapName $oidc.existingConfigUrlKey }}
  valueFrom:
    configMapKeyRef:
      name: {{ $oidc.existingConfigMapName | quote }}
      key: {{ $oidc.existingConfigUrlKey | quote }}
  {{- else }}
  value: {{ $oidc.configUrl | quote }}
  {{- end }}
- name: MINIO_IDENTITY_OPENID_CLIENT_ID
  {{- if and $oidc.existingClientSecretName $oidc.existingClientIdKey }}
  valueFrom:
    secretKeyRef:
      name: {{ $oidc.existingClientSecretName | quote }}
      key: {{ $oidc.existingClientIdKey | quote }}
  {{- else }}
  value: {{ $oidc.clientId | quote }}
  {{- end }}
- name: MINIO_IDENTITY_OPENID_CLIENT_SECRET
  {{- if and $oidc.existingClientSecretName $oidc.existingClientSecretKey }}
  valueFrom:
    secretKeyRef:
      name: {{ $oidc.existingClientSecretName | quote }}
      key: {{ $oidc.existingClientSecretKey | quote }}
  {{- else }}
  value: {{ $oidc.clientSecret | quote }}
  {{- end }}
- name: MINIO_IDENTITY_OPENID_CLAIM_NAME
  value: {{ $oidc.claimName | quote }}
- name: MINIO_IDENTITY_OPENID_CLAIM_PREFIX
  value: {{ $oidc.claimPrefix | quote }}
- name: MINIO_IDENTITY_OPENID_SCOPES
  value: {{ tpl $oidc.scopes . | quote }}
- name: MINIO_IDENTITY_OPENID_COMMENT
  value: {{ $oidc.comment | quote }}
{{- with $oidc.redirectUri }}
- name: MINIO_IDENTITY_OPENID_REDIRECT_URI
  value: {{ tpl . $ | quote }}
{{- end }}
{{- if and $oidc.redirectUrl (not (hasKey (.Values.environment | default dict) "MINIO_BROWSER_REDIRECT_URL")) }}
- name: MINIO_BROWSER_REDIRECT_URL
  value: {{ tpl $oidc.redirectUrl . | quote }}
{{- end }}
- name: MINIO_IDENTITY_OPENID_DISPLAY_NAME
  value: {{ $oidc.displayName | quote }}
{{- end }}
{{- end -}}

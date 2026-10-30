// Copyright (c) 2015-2026 MinIO, Inc.
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
	"fmt"
	"strings"
)

// Object naming modes. The mode is chosen when a cluster is formatted for the
// first time and can never be changed afterwards; it is persisted in
// format.json on every drive.
const (
	objectNamingSafe     = "safe"
	objectNamingExtended = "extended"
)

// Unicode markers used by the extended object naming mode.
//
// A user key is stored under an escaped form and, for regular objects, the
// final path component carries the terminal marker. Because the marker and
// every escape character are escaped inside user keys, an unescaped terminal
// marker on disk can only have been appended by the server. This restores the
// invariant that a directory holding an `xl.meta` never doubles as the parent
// directory of another key, so objects and their own prefixes can coexist:
//
//	obj1      -> <bucket>/obj1◊/xl.meta
//	obj1/obj2 -> <bucket>/obj1/obj2◊/xl.meta
//	obj1/     -> <bucket>/obj1__XLDIR__/xl.meta (directory objects keep __XLDIR__)
const (
	objectNamingEscape    = '␣' // ␣ escape character
	objectNamingTerminal  = '◊' // ◊ terminal marker for object names
	objectNamingDirSuffix = globalDirSuffix
)

// extendedNamingEscapes maps reserved user characters to the digit stored
// after the escape character.
var extendedNamingEscapes = map[rune]rune{
	'␣': '0', // ␣ escape character itself
	'⫽': '1', // ⫽ extra slash
	'◖': '2', // ◖ leading slash
	'◗': '3', // ◗ trailing slash
	'◊': '4', // ◊ terminal marker
	'◉': '5', // ◉
	'◈': '6', // ◈
	'◇': '7', // ◇
	'◆': '8', // ◆
	'⬡': '9', // ⬡
}

// extendedNamingUnescapes is the reverse of extendedNamingEscapes.
var extendedNamingUnescapes = func() map[rune]rune {
	m := make(map[rune]rune, len(extendedNamingEscapes))
	for r, d := range extendedNamingEscapes {
		m[d] = r
	}
	return m
}()

// isObjectNamingModeValid reports whether mode names a supported object naming
// mode. The empty string selects the default (safe) mode.
func isObjectNamingModeValid(mode string) bool {
	switch mode {
	case "", objectNamingSafe, objectNamingExtended:
		return true
	}
	return false
}

// normalizeObjectNamingMode returns the canonical mode string for a value
// passed through the --object-naming flag or MINIO_OBJECT_NAMING.
func normalizeObjectNamingMode(mode string) string {
	if mode == "" {
		return objectNamingSafe
	}
	return mode
}

// escapeExtendedNaming escapes every reserved character in s, leaving all
// other characters (including '/') untouched.
func escapeExtendedNaming(s string) string {
	// Fast path: most keys contain no reserved characters.
	idx := strings.IndexFunc(s, func(r rune) bool {
		_, ok := extendedNamingEscapes[r]
		return ok
	})
	if idx < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	b.WriteString(s[:idx])
	for _, r := range s[idx:] {
		if d, ok := extendedNamingEscapes[r]; ok {
			b.WriteRune(objectNamingEscape)
			b.WriteRune(d)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// unescapeExtendedNaming reverses escapeExtendedNaming. It never strips the
// terminal marker; callers must do that first.
func unescapeExtendedNaming(s string) string {
	if !strings.ContainsRune(s, objectNamingEscape) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == objectNamingEscape && i+1 < len(runes) {
			if orig, ok := extendedNamingUnescapes[runes[i+1]]; ok {
				b.WriteRune(orig)
				i++
				continue
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

// encodeExtendedObjectPath converts a user-domain object path to its on-disk
// form.
//
//   - Paths ending with the directory-object suffix have the suffix preserved
//     outside the escaped name and carry no terminal marker.
//   - Paths ending with '/' are treated as prefixes and are escaped only.
//   - All other paths are object names: escaped, with the terminal marker
//     appended to the final component.
func encodeExtendedObjectPath(object string) string {
	if strings.HasSuffix(object, objectNamingDirSuffix) {
		stem := strings.TrimSuffix(object, objectNamingDirSuffix)
		return escapeExtendedNaming(stem) + objectNamingDirSuffix
	}
	if strings.HasSuffix(object, SlashSeparator) {
		return escapeExtendedNaming(object)
	}
	return escapeExtendedNaming(object) + string(objectNamingTerminal)
}

// decodeExtendedObjectPath reverses encodeExtendedObjectPath for a
// disk-relative name. Directory-object names keep their __XLDIR__ suffix, which
// callers pass through decodeDirObject as before.
func decodeExtendedObjectPath(diskName string) string {
	if strings.HasSuffix(diskName, objectNamingDirSuffix) {
		stem := strings.TrimSuffix(diskName, objectNamingDirSuffix)
		return unescapeExtendedNaming(stem) + objectNamingDirSuffix
	}
	if strings.HasSuffix(diskName, string(objectNamingTerminal)) {
		diskName = strings.TrimSuffix(diskName, string(objectNamingTerminal))
	}
	return unescapeExtendedNaming(diskName)
}

// isExtendedObjectDirName reports whether a disk entry (without trailing '/')
// is a regular object directory, i.e. its final component carries the
// terminal marker.
func isExtendedObjectDirName(name string) bool {
	return strings.HasSuffix(name, string(objectNamingTerminal))
}

// encodeObjectName converts a user-domain object name into the form used
// inside the storage stack (set/erasure/storage layers). In safe mode this is
// the historical encodeDirObject (directory objects only). In extended mode
// every object is escaped and regular objects carry the terminal marker, so a
// directory holding an xl.meta can never double as another key's parent.
//
// The already-normalized directory-object form ("name__XLDIR__") is accepted
// as well and maps to the same disk name, so callers that carry that form (the
// scanner does, exactly as in safe mode) do not need to translate.
func encodeObjectName(object string) string {
	if !globalObjectNamingExtended {
		return encodeDirObject(object)
	}
	if strings.HasSuffix(object, SlashSeparator) {
		// Directory objects keep the legacy __XLDIR__ representation. The
		// suffix itself is preserved outside the escaped name.
		return escapeExtendedNaming(strings.TrimSuffix(object, SlashSeparator)) + objectNamingDirSuffix
	}
	if strings.HasSuffix(object, globalDirSuffix) {
		stem := strings.TrimSuffix(object, globalDirSuffix)
		return escapeExtendedNaming(stem) + objectNamingDirSuffix
	}
	return escapeExtendedNaming(object) + string(objectNamingTerminal)
}

// decodeObjectName reverses encodeObjectName for a stack-domain name.
func decodeObjectName(object string) string {
	if !globalObjectNamingExtended {
		return decodeDirObject(object)
	}
	if strings.HasSuffix(object, objectNamingDirSuffix) {
		return unescapeExtendedNaming(strings.TrimSuffix(object, objectNamingDirSuffix)) + SlashSeparator
	}
	if strings.HasSuffix(object, string(objectNamingTerminal)) {
		return unescapeExtendedNaming(strings.TrimSuffix(object, string(objectNamingTerminal)))
	}
	return unescapeExtendedNaming(object)
}

// encodeObjectNameForBucket applies the storage-stack name transformation for
// an object key in bucket. Meta buckets (.minio.sys, its tmp and multipart
// parts) keep their historical raw layout: those keys are generated by the
// server and contain none of the reserved characters, and keeping them raw
// lets internal tooling and older binaries read them.
func encodeObjectNameForBucket(bucket, object string) string {
	if isMinioMetaBucketName(bucket) {
		return object
	}
	return encodeObjectName(object)
}

// decodeObjectNameForBucket reverses encodeObjectNameForBucket.
func decodeObjectNameForBucket(bucket, object string) string {
	if isMinioMetaBucketName(bucket) {
		return object
	}
	return decodeObjectName(object)
}

// encodeObjectPrefixName converts a user-domain object prefix (a key that may
// or may not end with '/') into the form used to address the prefix directory
// tree in the storage stack. Unlike encodeObjectName it never produces a
// directory-object suffix or a terminal marker, because a prefix is not an
// object.
func encodeObjectPrefixName(prefix string) string {
	if !globalObjectNamingExtended {
		return prefix
	}
	return escapeExtendedNaming(prefix)
}

// decodeExtendedDiskPath decodes every component of a disk-relative path.
// Terminal markers are stripped (only object directory components carry one)
// and reserved characters are unescaped. Internal names (xl.meta, part files,
// UUID data directories) contain none of the reserved characters, so decoding
// them is a no-op. Directory-object suffixes are kept, as in safe mode.
func decodeExtendedDiskPath(rel string) string {
	if !globalObjectNamingExtended {
		return rel
	}
	parts := strings.Split(rel, SlashSeparator)
	for i, p := range parts {
		p = strings.TrimSuffix(p, string(objectNamingTerminal))
		parts[i] = unescapeExtendedNaming(p)
	}
	return strings.Join(parts, SlashSeparator)
}

// objectNamingModeMismatchError builds the startup error for inconsistent
// object naming modes across drives or pools.
func objectNamingModeMismatchError(found, expected string, source fmt.Stringer) error {
	return fmt.Errorf("drive %s has object naming mode %q, expected %q: object naming cannot be changed after the cluster was formatted", source, normalizeObjectNamingMode(found), normalizeObjectNamingMode(expected))
}

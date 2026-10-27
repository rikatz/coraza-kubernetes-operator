/*
Copyright Coraza Kubernetes Operator contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package validation provides Coraza validation helpers for rule text.
package validation

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3"

	"github.com/networking-incubator/coraza-kubernetes-operator/internal/rulesets/memfs"
)

// validationTrailer pins the validation WAF's audit writer to a discarded
// stream. Coraza opens the SecAuditLog target while compiling a WAF, regardless
// of SecAuditEngine, so tenant text could otherwise create or truncate any host
// file the operator can write. The delivered configuration is unaffected.
const validationTrailer = "\nSecAuditLogType Serial\nSecAuditLog /dev/null"

// BuildWAFConfig returns a validation WAF config whose root filesystem is
// always in-memory. Coraza falls back to io.OSFS when no root is set, so tenant
// rule text could otherwise read operator files (an Include of the ServiceAccount
// token leaks it through the compilation error into tenant-readable status).
// Runtime include aliases are stubbed so Coraza does not reject what the plugin
// resolves from its embedded filesystem.
func BuildWAFConfig(rules string, dataFiles map[string][]byte) coraza.WAFConfig {
	mfs := memfs.NewMemFS()
	for name, data := range dataFiles {
		mfs.WriteFile(name, data)
	}
	for _, target := range runtimeIncludeTargets(rules) {
		mfs.WriteFile(target, nil)
	}
	return coraza.NewWAFConfig().WithDirectives(rules + validationTrailer).WithRootFS(mfs)
}

// runtimeIncludeTargets returns the non-glob Include targets resolved by the
// plugin at runtime, so validation can stub them.
func runtimeIncludeTargets(rules string) []string {
	var targets []string
	for line := range strings.SplitSeq(joinActiveRuleLines(rules), "\n") {
		match := includePattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		target := strings.Trim(strings.TrimSpace(match[1]), `"'`)
		if isRuntimeResolvedPath(target) && !strings.Contains(target, "*") {
			targets = append(targets, target)
		}
	}
	return targets
}

// ExtractMissingFilePath returns the path from a missing-file error by walking
// the error chain for *fs.PathError with fs.ErrNotExist.
func ExtractMissingFilePath(err error) (string, bool) {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) && errors.Is(pathErr.Err, fs.ErrNotExist) {
		return pathErr.Path, true
	}
	return "", false
}

// ExtractMissingFileBasename extracts the base filename from a missing-file
// error by walking the error chain for *fs.PathError with fs.ErrNotExist.
func ExtractMissingFileBasename(err error) (string, bool) {
	path, ok := ExtractMissingFilePath(err)
	if !ok {
		return "", false
	}
	return filepath.Base(path), true
}

// isRuntimeResolvedPath reports whether the plugin's embedded filesystem
// resolves the path at runtime: @owasp_crs, @crs-setup-conf, @recommended-conf,
// @demo-conf and @ftw-conf. The operator cannot resolve them, so it must accept
// them.
func isRuntimeResolvedPath(path string) bool {
	return strings.HasPrefix(path, "@")
}

// isOSPath reports whether path addresses the operator's filesystem instead of
// a RuleData file name (absolute, parent-relative, Windows volume or UNC). Such
// paths are always rejected: only RuleData names and runtime aliases may be
// referenced.
func isOSPath(path string) bool {
	if path == "" {
		return false
	}
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) {
		return true
	}
	if len(path) >= 2 && path[1] == ':' { // C:\... or C:/...
		return true
	}
	return path == ".." || strings.HasPrefix(path, "../")
}

// SanitizeErrorMessage replaces filesystem paths in missing-file errors with
// just the base filename to prevent disclosure of container-internal paths.
func SanitizeErrorMessage(err error) error {
	if basename, ok := ExtractMissingFileBasename(err); ok {
		return fmt.Errorf("open %s: data does not exist", basename)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("validation failed: referenced file does not exist (path redacted)")
	}
	return err
}

// ShouldSkipMissingFileError reports whether a missing-file validation error
// should be skipped. A runtime alias (@owasp_crs/..., @crs-setup-conf, ...) is
// always skipped: the plugin's merged filesystem resolves it. Otherwise, when
// dataFiles is nil (RuleSource reconciler path, no RuleSet-scoped RuleData
// merged), any missing-file error is skipped so aggregate RuleSet validation
// remains authoritative for @pmFromFile. When dataFiles is non-nil, the error
// is skipped only if basename exists in the map (use an empty non-nil map to
// require resolution without providing files).
func ShouldSkipMissingFileError(err error, dataFiles map[string][]byte) bool {
	path, ok := ExtractMissingFilePath(err)
	if !ok {
		return false
	}
	if isRuntimeResolvedPath(path) {
		return true
	}
	if dataFiles == nil {
		return true
	}
	_, exists := dataFiles[filepath.Base(path)]
	return exists
}

// includePattern matches an Include directive and its whole argument in rule
// text already normalised by joinActiveRuleLines.
var includePattern = regexp.MustCompile(`(?i)^include[ \t]+(.+)$`)

// ValidateIncludes rejects Include targets that address the operator
// filesystem. The validation WAF has an in-memory root, so such a path cannot
// resolve anyway; rejecting it here keeps the error honest and independent of
// the missing-file skip that defers RuleData names to aggregate validation.
// Runtime aliases (@owasp_crs/..., @crs-setup-conf, ...) are accepted because
// the plugin resolves them from its embedded filesystem.
func ValidateIncludes(rules string) error {
	for line := range strings.SplitSeq(joinActiveRuleLines(rules), "\n") {
		match := includePattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		target := strings.Trim(strings.TrimSpace(match[1]), `"'`)
		if isRuntimeResolvedPath(target) || !isOSPath(target) {
			continue
		}
		return errors.New(`Include with an absolute or parent-relative path is not allowed: use @owasp_crs/..., @crs-setup-conf, @recommended-conf, @demo-conf, @ftw-conf or a RuleData file name`)
	}
	return nil
}

// ValidateRuleSourceRules validates SecLang rule text via Coraza. dataFiles
// supplies in-memory files for @pmFromFile resolution. nil means no files are
// provided: missing-file errors are skipped (RuleSource controller path).
// Pass a non-nil map (including an empty map) to require that missing files
// appear in the map. RuleSet aggregate validation remains authoritative for
// cross-source and full RuleData-backed rules.
func ValidateRuleSourceRules(rules, ruleSourceName string, dataFiles map[string][]byte) error {
	if IsPatchOnlyFragment(rules) {
		return nil
	}
	if err := ValidateIncludes(rules); err != nil {
		return fmt.Errorf("RuleSource %s doesn't contain valid rules: %w", ruleSourceName, err)
	}
	if _, err := coraza.NewWAF(BuildWAFConfig(rules, dataFiles)); err != nil {
		if ShouldSkipMissingFileError(err, dataFiles) {
			return nil
		}
		return fmt.Errorf("RuleSource %s doesn't contain valid rules: %w", ruleSourceName, SanitizeErrorMessage(err))
	}
	return nil
}

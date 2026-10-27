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
	"path"
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
// Runtime include aliases and embedded CRS data files are stubbed so Coraza
// does not reject what the plugin resolves from its embedded filesystem.
func BuildWAFConfig(rules string, dataFiles map[string][]byte) coraza.WAFConfig {
	mfs := memfs.NewMemFS()
	for name, data := range dataFiles {
		mfs.WriteFile(name, data)
	}
	for _, target := range append(runtimeIncludeTargets(rules), embeddedDataTargets(rules)...) {
		if _, ok := dataFiles[target]; !ok {
			mfs.WriteFile(target, nil)
		}
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

// embeddedDataTargets returns the @pmFromFile targets the plugin resolves from
// its embedded CRS tree, so validation can stub them.
func embeddedDataTargets(rules string) []string {
	var targets []string
	for _, match := range pmFromFilePattern.FindAllStringSubmatch(joinActiveRuleLines(rules), -1) {
		if len(match) < 3 {
			continue
		}
		target := path.Clean(strings.Trim(strings.TrimSpace(match[2]), `"'`))
		if isEmbeddedDataPath(target) {
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
// resolves the path at runtime. Only these aliases are resolvable there: any
// other @-prefixed target passes validation but makes the plugin NACK every
// push, which the operator cannot report because the Engine looks Ready.
// The four file aliases name a single embedded file. @owasp_crs/<path> maps to
// the embedded CRS tree, so the path must name a file inside it: the bare
// @owasp_crs and a path with an empty, "." or ".." segment name the directory
// itself, which cannot be included. A glob in the final segment (for example
// @owasp_crs/*.conf) is allowed: Coraza expands it against the embedded tree.
// A wrong file name there is a documented delivery risk: the operator cannot
// verify the embedded file list.
func isRuntimeResolvedPath(path string) bool {
	switch path {
	case "@recommended-conf", "@demo-conf", "@ftw-conf", "@crs-setup-conf":
		return true
	}
	rel, ok := strings.CutPrefix(path, "@owasp_crs/")
	if !ok {
		return false
	}
	for _, elem := range strings.Split(rel, "/") {
		if elem == "" || elem == "." || elem == ".." {
			return false
		}
	}
	return true
}

// isOSPath reports whether path addresses the operator's filesystem instead of
// a RuleData file name (absolute, parent-relative anywhere in the path, Windows
// volume or UNC). Such paths are always rejected: only RuleData names and
// runtime aliases may be referenced.
func isOSPath(path string) bool {
	if path == "" {
		return false
	}
	p := strings.ReplaceAll(path, `\`, "/")
	if strings.HasPrefix(p, "/") || (len(p) >= 2 && p[1] == ':') { // /... or C:\...
		return true
	}
	for elem := range strings.SplitSeq(p, "/") {
		if elem == ".." {
			return true
		}
	}
	return false
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

// forbiddenDirectivePattern matches directives that make Coraza open or create a
// host file while compiling a WAF, regardless of the in-memory root filesystem.
// SecDebugLogLevel is deliberately not matched: it only sets a verbosity and
// opens nothing. SecAuditLog and SecAuditLogType are allowed because
// validationTrailer overrides them to /dev/null.
var forbiddenDirectivePattern = regexp.MustCompile(`(?i)^(secdebuglog|secuploaddir)(?:[ \t]|$)`)

// uploadKeepFilesPattern matches SecUploadKeepFiles and its value. Only "Off" is
// accepted: every other value keeps uploaded files on disk, and the plugin has
// no upload directory.
var uploadKeepFilesPattern = regexp.MustCompile(`(?i)^secuploadkeepfiles(?:[ \t]+(\S+))?`)

// allowedIncludeTargets lists the reference forms a tenant may use. It is
// static so neither a rejected path nor rule content can leak into status.
const allowedIncludeTargets = "@recommended-conf, @demo-conf, @ftw-conf, @crs-setup-conf, @owasp_crs/<path> or a RuleData file name"

// ValidateIncludes rejects Include targets that address the operator
// filesystem, unresolvable aliases, and directives that write host files. The
// validation WAF has an in-memory root, so such a path cannot resolve anyway;
// rejecting it here keeps the error honest and independent of the missing-file
// skip that defers RuleData names to aggregate validation. Runtime aliases
// (@owasp_crs/..., @crs-setup-conf, ...) are accepted because the plugin
// resolves them from its embedded filesystem.
//
// dataFiles are the RuleData files merged for the RuleSet. An Include of a
// RuleData name is parsed as rule text, so the content of every included file
// is scanned too. @pmFromFile data is never parsed as SecLang and is not
// scanned: a blocklist that happens to contain the text of a forbidden
// directive is valid. Pass nil on the RuleSource path, which has no merged data.
func ValidateIncludes(rules string, dataFiles map[string][]byte) error {
	queue := []struct{ name, text string }{{text: rules}}
	scanned := make(map[string]struct{}, len(dataFiles))
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		included, err := validateRuleText(current.text)
		if err != nil {
			if current.name == "" {
				return err
			}
			return fmt.Errorf("included RuleData file %s: %w", current.name, err)
		}
		for _, name := range included {
			if _, seen := scanned[name]; seen {
				continue
			}
			data, ok := dataFiles[name]
			if !ok {
				continue
			}
			scanned[name] = struct{}{}
			queue = append(queue, struct{ name, text string }{name: name, text: string(data)})
		}
	}
	return nil
}

// validateRuleText rejects the directives and Include targets a tenant rule
// text (or an included data file) may not use. It returns the RuleData file
// names the text Includes, so the caller can scan their content too.
// shortcut: a glob Include is not expanded for scanning; Coraza still parses
// the matched files during compilation, which happens in the in-memory root.
func validateRuleText(rules string) ([]string, error) {
	// Coraza skips blank and comment lines before checking for a line
	// continuation, so a trailing "\" would swallow the first directive of
	// validationTrailer and report a confusing action error.
	lastContinued := false
	for line := range strings.SplitSeq(rules, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			lastContinued = strings.HasSuffix(line, `\`)
		}
	}
	if lastContinued {
		return nil, errors.New(`rule text ends with a line continuation: remove the trailing "\"`)
	}

	var included []string
	for line := range strings.SplitSeq(joinActiveRuleLines(rules), "\n") {
		if match := forbiddenDirectivePattern.FindStringSubmatch(line); match != nil {
			return nil, fmt.Errorf("%s is not allowed: rule validation must not write host files", match[1])
		}
		if match := uploadKeepFilesPattern.FindStringSubmatch(line); match != nil {
			if len(match) < 2 || !strings.EqualFold(strings.Trim(match[1], `"'`), "off") {
				return nil, errors.New("SecUploadKeepFiles is not allowed: rule validation must not write host files")
			}
		}
		match := includePattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		target := strings.Trim(strings.TrimSpace(match[1]), `"'`)
		switch {
		case isOSPath(target):
			return nil, errors.New(`Include with an absolute or parent-relative path is not allowed: use ` + allowedIncludeTargets)
		case strings.HasPrefix(target, "@"):
			if !isRuntimeResolvedPath(target) {
				return nil, errors.New(`Include alias is not resolved by the plugin: use ` + allowedIncludeTargets)
			}
		default:
			included = append(included, path.Clean(target))
		}
	}
	return included, nil
}

// ValidateRuleSourceRules validates SecLang rule text via Coraza. dataFiles
// supplies in-memory files for @pmFromFile resolution. nil means no files are
// provided: missing-file errors are skipped (RuleSource controller path).
// Pass a non-nil map (including an empty map) to require that missing files
// appear in the map. RuleSet aggregate validation remains authoritative for
// cross-source and full RuleData-backed rules.
func ValidateRuleSourceRules(rules, ruleSourceName string, dataFiles map[string][]byte) error {
	// The guard is cheap and applies to patch-only fragments too: they are
	// skipped by Coraza, not by the directive and alias rules.
	if err := ValidateIncludes(rules, dataFiles); err != nil {
		return fmt.Errorf("RuleSource %s doesn't contain valid rules: %w", ruleSourceName, err)
	}
	if IsPatchOnlyFragment(rules) {
		return nil
	}
	if _, err := coraza.NewWAF(BuildWAFConfig(rules, dataFiles)); err != nil {
		if ShouldSkipMissingFileError(err, dataFiles) {
			return nil
		}
		return fmt.Errorf("RuleSource %s doesn't contain valid rules: %w", ruleSourceName, SanitizeErrorMessage(err))
	}
	return nil
}

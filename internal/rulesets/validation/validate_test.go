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

package validation

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractMissingFileBasename(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantBase string
		wantOK   bool
	}{
		{
			name:     "bare PathError with ErrNotExist",
			err:      &fs.PathError{Op: "open", Path: "/var/lib/data/rules.conf", Err: fs.ErrNotExist},
			wantBase: "rules.conf",
			wantOK:   true,
		},
		{
			name:     "single-wrapped PathError",
			err:      fmt.Errorf("outer: %w", &fs.PathError{Op: "open", Path: "/secret/path/file.data", Err: fs.ErrNotExist}),
			wantBase: "file.data",
			wantOK:   true,
		},
		{
			name: "double-wrapped PathError (Coraza style)",
			err: fmt.Errorf("invalid WAF config from string: %w",
				fmt.Errorf("failed to compile the directive \"secrule\": %w",
					&fs.PathError{Op: "open", Path: "/app/rules/modsec.data", Err: fs.ErrNotExist})),
			wantBase: "modsec.data",
			wantOK:   true,
		},
		{
			name:     "relative path",
			err:      &fs.PathError{Op: "open", Path: "relative/file.txt", Err: fs.ErrNotExist},
			wantBase: "file.txt",
			wantOK:   true,
		},
		{
			name:     "PathError Op stat (not just open)",
			err:      &fs.PathError{Op: "stat", Path: "/var/lib/waf/stats.data", Err: fs.ErrNotExist},
			wantBase: "stats.data",
			wantOK:   true,
		},
		{
			name:     "PathError with syscall.ENOENT (Unix)",
			err:      &fs.PathError{Op: "open", Path: "/etc/coraza/x.data", Err: syscall.ENOENT},
			wantBase: "x.data",
			wantOK:   true,
		},
		{
			name:     "PathError with different Err (not ErrNotExist)",
			err:      &fs.PathError{Op: "open", Path: "/some/path", Err: fs.ErrPermission},
			wantBase: "",
			wantOK:   false,
		},
		{
			name:     "non-PathError",
			err:      errors.New("completely unrelated error"),
			wantBase: "",
			wantOK:   false,
		},
		{
			name:     "ErrNotExist without PathError wrapper",
			err:      fmt.Errorf("something went wrong: %w", fs.ErrNotExist),
			wantBase: "",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, ok := ExtractMissingFileBasename(tt.err)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantBase, base)
		})
	}
}

func TestSanitizeErrorMessage(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		wantSubstring string
		wantNoAbsPath bool
	}{
		{
			name:          "PathError sanitized to basename",
			err:           &fs.PathError{Op: "open", Path: "/var/lib/operator/secret.data", Err: fs.ErrNotExist},
			wantSubstring: "open secret.data: data does not exist",
			wantNoAbsPath: true,
		},
		{
			name: "wrapped PathError sanitized",
			err: fmt.Errorf("invalid WAF config: %w",
				&fs.PathError{Op: "open", Path: "/deep/nested/path/file.conf", Err: fs.ErrNotExist}),
			wantSubstring: "open file.conf: data does not exist",
			wantNoAbsPath: true,
		},
		{
			name:          "ErrNotExist without PathError gets generic redaction",
			err:           fmt.Errorf("something: %w", fs.ErrNotExist),
			wantSubstring: "referenced file does not exist (path redacted)",
			wantNoAbsPath: true,
		},
		{
			name:          "non-file error passes through",
			err:           errors.New("syntax error in directive"),
			wantSubstring: "syntax error in directive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeErrorMessage(tt.err)
			assert.Contains(t, result.Error(), tt.wantSubstring)
			if tt.wantNoAbsPath {
				assert.False(t, strings.Contains(result.Error(), "/var/"),
					"sanitized error should not contain absolute paths")
				assert.False(t, strings.Contains(result.Error(), "/deep/"),
					"sanitized error should not contain absolute paths")
			}
		})
	}
}

func TestSanitizeErrorMessage_NoAbsolutePathLeak(t *testing.T) {
	paths := []string{
		"/var/lib/operator/data/rules.data",
		"/etc/coraza/secrets/api-keys.conf",
		"/tmp/waf-runtime/cache/modsec.data",
		"/home/operator/.config/rules.txt",
	}
	for _, p := range paths {
		err := &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
		result := SanitizeErrorMessage(err).Error()
		assert.False(t, strings.Contains(result, "/"),
			"sanitized output for path %q should not contain any '/' but got: %s", p, result)
	}
}

func TestShouldSkipMissingFileError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		secretData map[string][]byte
		want       bool
	}{
		{
			name:       "nil secretData skips a relative missing file (defer to aggregate)",
			err:        &fs.PathError{Op: "open", Path: "rule.data", Err: fs.ErrNotExist},
			secretData: nil,
			want:       true,
		},
		{
			name:       "basename found in secretData",
			err:        &fs.PathError{Op: "open", Path: "rule.data", Err: fs.ErrNotExist},
			secretData: map[string][]byte{"rule.data": []byte("content")},
			want:       true,
		},
		{
			name: "wrapped PathError, basename found",
			err: fmt.Errorf("outer: %w",
				&fs.PathError{Op: "open", Path: "found.data", Err: fs.ErrNotExist}),
			secretData: map[string][]byte{"found.data": []byte("x")},
			want:       true,
		},
		{
			name:       "basename not in secretData",
			err:        &fs.PathError{Op: "open", Path: "missing.data", Err: fs.ErrNotExist},
			secretData: map[string][]byte{"other.data": []byte("content")},
			want:       false,
		},
		{
			name:       "non-PathError returns false",
			err:        errors.New("generic error"),
			secretData: map[string][]byte{"anything": []byte("x")},
			want:       false,
		},
		{
			name:       "ErrNotExist without PathError returns false",
			err:        fmt.Errorf("wrapped: %w", fs.ErrNotExist),
			secretData: map[string][]byte{"anything": []byte("x")},
			want:       false,
		},
		{
			name:       "PathError with ErrPermission returns false",
			err:        &fs.PathError{Op: "open", Path: "file.data", Err: fs.ErrPermission},
			secretData: map[string][]byte{"file.data": []byte("x")},
			want:       false,
		},
		{
			name:       "runtime alias is skipped with nil dataFiles",
			err:        &fs.PathError{Op: "open", Path: "@recommended-conf", Err: fs.ErrNotExist},
			secretData: nil,
			want:       true,
		},
		{
			name:       "runtime alias is skipped with an empty data file map",
			err:        &fs.PathError{Op: "open", Path: "@owasp_crs/REQUEST-901-INITIALIZATION.conf", Err: fs.ErrNotExist},
			secretData: map[string][]byte{},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldSkipMissingFileError(tt.err, tt.secretData)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestValidateRuleSourceRules(t *testing.T) {
	t.Run("valid rules return nil", func(t *testing.T) {
		err := ValidateRuleSourceRules(`SecDefaultAction "phase:1,log,auditlog,pass"`, "test-rs", nil)
		assert.NoError(t, err)
	})

	t.Run("invalid rules return error mentioning RuleSource name", func(t *testing.T) {
		err := ValidateRuleSourceRules(`SecInvalidDirective "bad"`, "bad-rs", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bad-rs")
		assert.Contains(t, err.Error(), "doesn't contain valid rules")
	})

	t.Run("missing file error is skipped when file exists in dataFiles", func(t *testing.T) {
		dataFiles := map[string][]byte{"rule1.data": []byte("content")}
		err := ValidateRuleSourceRules(
			`SecRule REQUEST_URI "@pmFromFile rule1.data" "id:1,phase:1,deny"`,
			"data-rs", dataFiles,
		)
		assert.NoError(t, err)
	})

	t.Run("missing file error is reported when file not in non-nil dataFiles", func(t *testing.T) {
		err := ValidateRuleSourceRules(
			`SecRule REQUEST_URI "@pmFromFile missing.data" "id:1,phase:1,deny"`,
			"data-rs", map[string][]byte{},
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "data-rs")
		msg := err.Error()
		if strings.Contains(msg, "/") {
			for _, leak := range []string{"/var/", "/etc/", "/tmp/", "/app/", "/root/"} {
				assert.NotContains(t, msg, leak, "validation error leaked a filesystem path segment")
			}
		}
	})

	t.Run("nil dataFiles skips missing file for operator validation path", func(t *testing.T) {
		err := ValidateRuleSourceRules(
			`SecRule REQUEST_URI "@pmFromFile only-at-ruleset.data" "id:1,phase:1,deny"`,
			"defer-rs", nil,
		)
		assert.NoError(t, err)
	})
}

// TestValidateRuleSourceRulesCannotReadHostFiles covers the tenant-text escape
// where Coraza's default io.OSFS read an operator file and its content leaked
// through the compilation error into tenant-readable status.
func TestValidateRuleSourceRulesCannotReadHostFiles(t *testing.T) {
	const marker = "operator-secret-marker-4f2c"
	secret := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(secret, []byte(marker+"\n"), 0o600))

	for _, include := range []string{
		"Include " + secret,
		"Include /var/run/secrets/kubernetes.io/serviceaccount/token",
		"Include /proc/self/environ",
		"Include ../etc/passwd",
		`Include C:\Windows\win.ini`,
	} {
		t.Run(include, func(t *testing.T) {
			err := ValidateRuleSourceRules(include, "probe-rs", nil)
			require.Error(t, err, "an OS path must be rejected, not silently skipped")
			assert.Contains(t, err.Error(), "probe-rs")
			assert.NotContains(t, err.Error(), marker, "the error must not contain file content")
		})
	}

	t.Run("/proc/self/environ content is not disclosed", func(t *testing.T) {
		t.Setenv("CKO_VALIDATION_PROBE", marker)
		err := ValidateRuleSourceRules("Include /proc/self/environ", "environ-rs", nil)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), marker)
	})

	// The same regression directly on the validation WAF: with an empty
	// in-memory root, no directive may read an arbitrary OS file.
	t.Run("validation WAF cannot read an existing OS file", func(t *testing.T) {
		for _, rules := range []string{
			"Include " + secret,
			`SecRule ARGS "@pmFromFile ` + secret + `" "id:1,phase:1,pass"`,
		} {
			_, err := coraza.NewWAF(BuildWAFConfig(rules, nil))
			require.Error(t, err)
			assert.NotContains(t, err.Error(), marker)
		}
	})

	t.Run("audit log configuration does not touch the host filesystem", func(t *testing.T) {
		auditPath := filepath.Join(t.TempDir(), "audit.log")
		err := ValidateRuleSourceRules(
			"SecRuleEngine On\nSecAuditEngine On\nSecAuditLog "+auditPath+"\nSecAuditLogType Serial",
			"audit-rs", nil,
		)
		require.NoError(t, err)
		_, statErr := os.Stat(auditPath)
		assert.True(t, os.IsNotExist(statErr), "the validation WAF must not create the audit log on the host")
	})
}

func TestValidateIncludes(t *testing.T) {
	for _, rules := range []string{
		"Include /etc/passwd",
		"Include /var/run/secrets/kubernetes.io/serviceaccount/token",
		"Include ../etc/passwd",
		"Include ..",
		"Include SomeData/../../../etc/passwd",
		"Include data/../../etc/passwd",
		`Include SomeData\..\..\..\etc\passwd`,
		`Include C:\Windows\win.ini`,
		"Include /etc/passwd /etc/shadow",
		"Include \\\n/etc/passwd",
		"SecRuleEngine On\ninclude '/etc/passwd'",
	} {
		t.Run(rules, func(t *testing.T) {
			require.Error(t, ValidateIncludes(rules, nil), "an OS path include must be rejected")
		})
	}

	for _, rules := range []string{
		"Include @recommended-conf",
		"Include @demo-conf",
		"Include @ftw-conf",
		"Include @crs-setup-conf",
		"Include @owasp_crs/*.conf",
		"Include @owasp_crs/REQUEST-*.conf",
		"Include @owasp_crs/REQUEST-901-INITIALIZATION.conf",
		"Include some.data",
		"Include ./some.data",
		"SecRuleEngine On\nSecRule ARGS \"@rx x\" \"id:1,phase:1,pass\"",
		"SecDebugLogLevel 9",
		"SecAuditLog /tmp/audit.log\nSecAuditLogType Serial",
	} {
		t.Run(rules, func(t *testing.T) {
			assert.NoError(t, ValidateIncludes(rules, nil))
		})
	}
}

// TestValidateIncludesRejectsUnresolvableGlobs covers globs the plugin cannot
// expand: only @owasp_crs/ patterns ending in .conf are resolvable, and a
// root-level glob matches nothing in either filesystem.
func TestValidateIncludesRejectsUnresolvableGlobs(t *testing.T) {
	for _, target := range []string{
		"@owasp_crs/*",
		"@owasp_crs/*.data",
		"@owasp_crs/REQUEST-*.data",
		"@owasp_crs/*/*.conf",
		"@owasp_crs/*/REQUEST-901-INITIALIZATION.conf",
		"@recommended-conf*",
		"*.conf",
		"rules/*.conf",
		"./*.conf",
	} {
		t.Run(target, func(t *testing.T) {
			err := ValidateIncludes("Include "+target, nil)
			require.Error(t, err, "the plugin cannot expand this glob")
			assert.Contains(t, err.Error(), "@owasp_crs/<path>", "the error must name the allowed aliases")
		})
	}
}

// TestValidateIncludesNestedIncludeResolvesRelativeToIncludingFile covers a
// nested Include: Coraza joins the target to the including file's directory,
// so the guard must scan that file, not a same-named file at the root.
func TestValidateIncludesNestedIncludeResolvesRelativeToIncludingFile(t *testing.T) {
	dataFiles := map[string][]byte{
		"sub/a.data": []byte("Include b.data"),
		"b.data":     []byte("SecDebugLog /dev/stdout"),
		"sub/b.data": []byte("SecRuleEngine On"),
	}

	require.NoError(t, ValidateIncludes("Include sub/a.data", dataFiles),
		"the root-level b.data is not the file Coraza parses")

	dataFiles["sub/b.data"] = []byte("SecDebugLog /dev/stdout")
	err := ValidateIncludes("Include sub/a.data", dataFiles)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "included RuleData file sub/b.data")
}

// TestValidateIncludesRejectsUnknownAliases covers the alias allowlist: an
// alias the plugin does not resolve makes the plugin NACK every push while the
// Engine looks Ready, so it must fail validation instead.
func TestValidateIncludesRejectsUnknownAliases(t *testing.T) {
	for _, target := range []string{
		"@notanalias",
		"@",
		"@crs-setup",
		"@OWASP_CRS/REQUEST-901-INITIALIZATION.conf",
		"@owasp_crsx/open.conf",
		"@owasp_crs/../setup.conf",
		"@owasp_crs/./open.conf",
		"@owasp_crs//open.conf",
		"@owasp_crs/open/./nested.conf",
		"@recommended-conf-extra",
	} {
		t.Run(target, func(t *testing.T) {
			err := ValidateIncludes("Include "+target, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "@owasp_crs/<path>", "the error must name the allowed aliases")
			assert.NotContains(t, err.Error(), "notanalias")
		})
	}

	// The bare alias names the embedded directory, not a file: the plugin has no
	// file mapping for it, so it would NACK every push.
	for _, target := range []string{"@owasp_crs", "@owasp_crs/"} {
		t.Run(target, func(t *testing.T) {
			err := ValidateIncludes("Include "+target, nil)
			require.Error(t, err, "the bare CRS directory cannot be included")
			assert.Contains(t, err.Error(), "@owasp_crs/<path>")
		})
	}

	// Documented trade: the operator cannot verify the embedded file list, so a
	// wrong file under @owasp_crs/ passes validation and NACKs in the plugin.
	assert.NoError(t, ValidateIncludes("Include @owasp_crs/typo.conf", nil))
}

// TestValidateIncludesRejectsHostWritingDirectives covers the directives that
// make Coraza create or append host files while compiling a WAF. The error must
// be static: tenant-controlled paths and rule content stay out of status.
func TestValidateIncludesRejectsHostWritingDirectives(t *testing.T) {
	const marker = "tenant-path-marker-7b1d"
	for _, rules := range []string{
		"SecDebugLog /dev/stdout",
		"SecDebugLog /dev/shm/" + marker + ".log",
		"SecDebugLogLevel 9\nSecDebugLog /dev/stdout",
		"secdebuglog /dev/stdout",
		"SecUploadDir /dev/shm/" + marker,
		"SecUploadKeepFiles On",
		"SecUploadKeepFiles",
		"SecUploadKeepFiles \"On\"",
		"secuploadkeepfiles on",
	} {
		t.Run(rules, func(t *testing.T) {
			err := ValidateIncludes(rules, nil)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), marker)
			assert.NotContains(t, err.Error(), "/dev/")
			assert.NotContains(t, err.Error(), "shm")
		})
	}

	assert.NoError(t, ValidateIncludes("SecDebugLogLevel 9", nil))
	assert.NoError(t, ValidateIncludes("SecDebugLog2 /dev/stdout", nil))
	// "Off" has no host effect and appears in stock CRS snippets.
	assert.NoError(t, ValidateIncludes("SecUploadKeepFiles Off", nil))
	assert.NoError(t, ValidateIncludes("SecUploadKeepFiles \"Off\"", nil))
}

func TestValidateRuleSourceRulesAcceptsRuntimeAliases(t *testing.T) {
	for _, include := range []string{
		"Include @recommended-conf",
		"Include @demo-conf",
		"Include @ftw-conf",
		"Include @crs-setup-conf",
		"SecRuleEngine On\nInclude @crs-setup-conf\nInclude @owasp_crs/*.conf",
		"Include @owasp_crs/REQUEST-901-INITIALIZATION.conf",
	} {
		t.Run(include, func(t *testing.T) {
			assert.NoError(t, ValidateRuleSourceRules(include, "alias-rs", nil), "the plugin resolves this include at runtime")
			assert.NoError(t, ValidateRuleSourceRules(include, "alias-rs", map[string][]byte{}))
		})
	}

	// The bare directory alias cannot be resolved to a file by the plugin.
	for _, include := range []string{"Include @owasp_crs", "Include @owasp_crs/"} {
		t.Run(include, func(t *testing.T) {
			err := ValidateRuleSourceRules(include, "alias-rs", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "alias-rs")
			assert.Contains(t, err.Error(), "@owasp_crs/<path>")
		})
	}
}

// TestValidateRuleSourceRulesRejectsUnknownAlias covers the RuleSource entry
// point: an alias the plugin cannot resolve must fail before the Engine looks
// Ready and the plugin NACKs.
func TestValidateRuleSourceRulesRejectsUnknownAlias(t *testing.T) {
	err := ValidateRuleSourceRules("Include @notanalias", "alias-rs", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "alias-rs")
	assert.Contains(t, err.Error(), "@owasp_crs/<path>")
	assert.NotContains(t, err.Error(), "notanalias")
}

// TestValidateRuleSourceRulesScansPatchOnlyFragments covers patch-only
// fragments, which skip Coraza but still carry Include directives the plugin
// must resolve.
func TestValidateRuleSourceRulesScansPatchOnlyFragments(t *testing.T) {
	rules := "SecRuleRemoveById 1\nInclude @notanalias"
	assert.True(t, IsPatchOnlyFragment(rules), "test requires a patch-only fragment")
	require.NoError(t, ValidateRuleSourceRules("SecRuleRemoveById 1", "patch-rs", nil))

	err := ValidateRuleSourceRules(rules, "patch-rs", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "patch-rs")
	assert.Contains(t, err.Error(), "@owasp_crs/<path>")
}

// TestValidateRuleSourceRulesRejectsDebugLog covers the RuleSource entry point:
// SecDebugLog must not reach NewWAF, which opens the path on the host.
func TestValidateRuleSourceRulesRejectsDebugLog(t *testing.T) {
	const marker = "probe-debug-marker-56af"
	debugLog := filepath.Join(t.TempDir(), marker+".log")

	err := ValidateRuleSourceRules(
		"SecRuleEngine On\nSecDebugLogLevel 9\nSecDebugLog "+debugLog,
		"debug-rs", nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "debug-rs")
	assert.NotContains(t, err.Error(), marker, "the error must not echo the tenant path")

	_, statErr := os.Stat(debugLog)
	assert.True(t, os.IsNotExist(statErr), "rejected rules must not create the debug log on the host")
}

// TestValidateIncludesScansIncludedDataFiles covers a RuleData file that the
// rule text Includes: Coraza parses an included file as rule text, so a
// host-writing directive hidden there must be rejected too. A @pmFromFile data
// file is never parsed as SecLang, so directive text inside it is just data.
func TestValidateIncludesScansIncludedDataFiles(t *testing.T) {
	const marker = "data-content-marker-2c94"
	dataFiles := map[string][]byte{
		"bad.data": []byte("SecDebugLog /dev/shm/" + marker + "\n"),
	}

	err := ValidateIncludes("Include bad.data", dataFiles)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad.data")
	assert.NotContains(t, err.Error(), marker)

	err = ValidateRuleSourceRules("Include bad.data", "data-rs", dataFiles)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data-rs")
	assert.NotContains(t, err.Error(), marker)

	assert.NoError(t, ValidateIncludes("Include good.data", map[string][]byte{
		"good.data": []byte("word\nother-word\n"),
	}))

	// A blocklist that contains the text of a forbidden directive is a valid
	// pattern file: @pmFromFile data is not SecLang.
	pmfRules := `SecRule ARGS "@pmf blocklist.data" "id:1,phase:1,deny"`
	blocklist := map[string][]byte{
		"blocklist.data": []byte("evilmonkey\nSecUploadDir /tmp\nSecDebugLog /dev/stdout\n"),
	}
	assert.NoError(t, ValidateIncludes(pmfRules, blocklist))
	assert.NoError(t, ValidateRuleSourceRules(pmfRules, "pmf-rs", blocklist))

	// An included file that Includes another RuleData file is parsed too, so its
	// content is reached by the scan.
	nested := map[string][]byte{
		"outer.data": []byte("Include inner.data\n"),
		"inner.data": []byte("SecDebugLog /dev/shm/" + marker + "\n"),
	}
	err = ValidateIncludes("Include outer.data", nested)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inner.data")
	assert.NotContains(t, err.Error(), marker)
}

// TestBuildWAFConfigSecDebugLogWritesHostFile documents why SecDebugLog is
// rejected: the validation WAF itself opens the tenant path on the host.
func TestBuildWAFConfigSecDebugLogWritesHostFile(t *testing.T) {
	debugLog := filepath.Join(t.TempDir(), "debug.log")
	_, err := coraza.NewWAF(BuildWAFConfig("SecDebugLog "+debugLog+"\nSecDebugLogLevel 9", nil))
	require.NoError(t, err)

	_, statErr := os.Stat(debugLog)
	assert.NoError(t, statErr, "without the validation guard Coraza creates the debug log on the host")
}

// TestBuildWAFConfigTrailerIsNotGlued covers rule text that ends in a line
// continuation: Coraza skips blank lines before joining a continued line, so
// the trailer's first directive would be swallowed into the last rule and
// compilation would fail with a confusing action error. The guard rejects it.
func TestBuildWAFConfigTrailerIsNotGlued(t *testing.T) {
	rules := "SecRuleEngine On\nSecRule ARGS \"@rx x\" \"id:1,phase:1,pass\"\\\n"

	for _, check := range []func(string, string, map[string][]byte) error{
		func(rules, _ string, dataFiles map[string][]byte) error { return ValidateIncludes(rules, dataFiles) },
		ValidateRuleSourceRules,
	} {
		err := check(rules, "continuation-rs", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "line continuation")
		assert.NotContains(t, err.Error(), "SecAuditLogType")
	}

	// The same rules with the trailing continuation removed compile normally.
	_, err := coraza.NewWAF(BuildWAFConfig(strings.TrimSuffix(rules, "\\\n"), nil))
	require.NoError(t, err)
}

// TestBuildWAFConfigStubsEmbeddedCRSData covers the embedded CRS data a tenant
// references from its own rules: the plugin serves crs/... from its module, so
// the validation WAF must not fail on it.
func TestBuildWAFConfigStubsEmbeddedCRSData(t *testing.T) {
	_, err := coraza.NewWAF(BuildWAFConfig(
		"SecRule ARGS \"@pmf crs/restricted-files.data\" \"id:1,phase:1,pass\"", nil))
	require.NoError(t, err)
}

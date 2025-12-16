package scimfilter

import (
	"fmt"
	"regexp"
	"strings"
)

// ResourceType indicates which SCIM resource we're filtering
type ResourceType int

const (
	ResourceTypeUser ResourceType = iota
	ResourceTypeGroup
)

// isValidAttributeName validates that an attribute name only contains safe characters.
// Per RFC 7643, SCIM attribute names must match: ALPHA *(ALPHA / DIGIT / "-" / "_")
var validAttributeNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)

func isValidAttributeName(name string) bool {
	return validAttributeNamePattern.MatchString(name)
}

// normalizeFilterBooleans quotes unquoted boolean values in SCIM filter strings.
// The SCIM RFC allows both `active eq true` and `active eq "true"`, but the
// scim2/filter-parser library only supports quoted values.
var unquotedBoolPattern = regexp.MustCompile(`\b(eq|ne)\s+(true|false)\b`)

func normalizeFilterBooleans(filter string) string {
	return unquotedBoolPattern.ReplaceAllString(filter, `$1 "$2"`)
}

// parseBoolValue parses a boolean value from a SCIM filter string
func parseBoolValue(s string) (bool, error) {
	s = strings.ToLower(strings.Trim(s, `"`))
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %q (must be true or false)", s)
	}
}

// escapePattern escapes special characters for LIKE/ILIKE patterns
func escapePattern(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

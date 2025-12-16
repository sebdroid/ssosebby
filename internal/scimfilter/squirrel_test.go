package scimfilter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseToSquirrel_UserFilters(t *testing.T) {
	tests := []struct {
		name     string
		filter   string
		wantSQL  string
		wantArgs []any
		wantErr  bool
	}{
		{
			name:     "empty filter",
			filter:   "",
			wantSQL:  "",
			wantArgs: nil,
		},
		{
			name:     "userName eq",
			filter:   `userName eq "john@example.com"`,
			wantSQL:  "email = ?",
			wantArgs: []any{"john@example.com"},
		},
		{
			name:     "active eq true",
			filter:   `active eq true`,
			wantSQL:  "(attributes->>'active')::boolean = ?",
			wantArgs: []any{true},
		},
		{
			name:     "active eq false",
			filter:   `active eq false`,
			wantSQL:  "(attributes->>'active')::boolean = ?",
			wantArgs: []any{false},
		},
		{
			name:     "userName AND active",
			filter:   `userName eq "john@example.com" and active eq true`,
			wantSQL:  "(email = ? AND (attributes->>'active')::boolean = ?)",
			wantArgs: []any{"john@example.com", true},
		},
		{
			name:     "userName OR active",
			filter:   `userName eq "john@example.com" or active eq false`,
			wantSQL:  "(email = ? OR (attributes->>'active')::boolean = ?)",
			wantArgs: []any{"john@example.com", false},
		},
		{
			name:     "NOT active",
			filter:   `not active eq true`,
			wantSQL:  "NOT ((attributes->>'active')::boolean = ?)",
			wantArgs: []any{true},
		},
		{
			name:     "complex filter with parentheses",
			filter:   `active eq true and (userName co "@acme" or userName co "@corp")`,
			wantSQL:  "((attributes->>'active')::boolean = ? AND (email ILIKE ? OR email ILIKE ?))",
			wantArgs: []any{true, "%@acme%", "%@corp%"},
		},
		{
			name:     "userName co (contains)",
			filter:   `userName co "acme"`,
			wantSQL:  "email ILIKE ?",
			wantArgs: []any{"%acme%"},
		},
		{
			name:     "userName sw (starts with)",
			filter:   `userName sw "john"`,
			wantSQL:  "email ILIKE ?",
			wantArgs: []any{"john%"},
		},
		{
			name:     "userName ew (ends with)",
			filter:   `userName ew "@example.com"`,
			wantSQL:  "email ILIKE ?",
			wantArgs: []any{"%@example.com"},
		},
		{
			name:     "userName ne (not equal)",
			filter:   `userName ne "john@example.com"`,
			wantSQL:  "email <> ?",
			wantArgs: []any{"john@example.com"},
		},
		{
			name:     "externalId eq",
			filter:   `externalId eq "ext-123"`,
			wantSQL:  "(attributes->>'externalId') = ?",
			wantArgs: []any{"ext-123"},
		},
		{
			name:     "displayName eq",
			filter:   `displayName eq "John Doe"`,
			wantSQL:  "(attributes->>'displayName') = ?",
			wantArgs: []any{"John Doe"},
		},
		// name sub-attributes (indexed) - sub-attributes preserve case for JSONB key matching
		{
			name:     "name.givenName eq",
			filter:   `name.givenName eq "John"`,
			wantSQL:  "(attributes->'name'->>'givenName') = ?",
			wantArgs: []any{"John"},
		},
		{
			name:     "name.familyName eq",
			filter:   `name.familyName eq "Doe"`,
			wantSQL:  "(attributes->'name'->>'familyName') = ?",
			wantArgs: []any{"Doe"},
		},
		{
			name:     "name.givenName co",
			filter:   `name.givenName co "Jo"`,
			wantSQL:  "(attributes->'name'->>'givenName') ILIKE ?",
			wantArgs: []any{"%Jo%"},
		},
		// title (indexed)
		{
			name:     "title eq",
			filter:   `title eq "Software Engineer"`,
			wantSQL:  "(attributes->>'title') = ?",
			wantArgs: []any{"Software Engineer"},
		},
		{
			name:     "title co",
			filter:   `title co "Engineer"`,
			wantSQL:  "(attributes->>'title') ILIKE ?",
			wantArgs: []any{"%Engineer%"},
		},
		// userType (indexed)
		{
			name:     "userType eq",
			filter:   `userType eq "Employee"`,
			wantSQL:  "(attributes->>'userType') = ?",
			wantArgs: []any{"Employee"},
		},
		{
			name:     "userType ne",
			filter:   `userType ne "Contractor"`,
			wantSQL:  "(attributes->>'userType') <> ?",
			wantArgs: []any{"Contractor"},
		},
		// preferredLanguage (indexed)
		{
			name:     "preferredLanguage eq",
			filter:   `preferredLanguage eq "en-US"`,
			wantSQL:  "(attributes->>'preferredLanguage') = ?",
			wantArgs: []any{"en-US"},
		},
		// locale (indexed)
		{
			name:     "locale eq",
			filter:   `locale eq "en_US"`,
			wantSQL:  "(attributes->>'locale') = ?",
			wantArgs: []any{"en_US"},
		},
		// timezone (indexed)
		{
			name:     "timezone eq",
			filter:   `timezone eq "America/Los_Angeles"`,
			wantSQL:  "(attributes->>'timezone') = ?",
			wantArgs: []any{"America/Los_Angeles"},
		},
		// Combined filter using multiple indexed attributes
		{
			name:     "combined indexed attributes",
			filter:   `userType eq "Employee" and title co "Engineer"`,
			wantSQL:  "((attributes->>'userType') = ? AND (attributes->>'title') ILIKE ?)",
			wantArgs: []any{"Employee", "%Engineer%"},
		},
		// Complex filters with multiple conditions
		{
			name:     "complex: active AND (email domain OR userType)",
			filter:   `active eq true and (userName ew "@acme.com" or userType eq "Admin")`,
			wantSQL:  "((attributes->>'active')::boolean = ? AND (email ILIKE ? OR (attributes->>'userType') = ?))",
			wantArgs: []any{true, "%@acme.com", "Admin"},
		},
		{
			name:     "complex: nested OR with AND",
			filter:   `(name.givenName eq "John" or name.givenName eq "Jane") and active eq true`,
			wantSQL:  "(((attributes->'name'->>'givenName') = ? OR (attributes->'name'->>'givenName') = ?) AND (attributes->>'active')::boolean = ?)",
			wantArgs: []any{"John", "Jane", true},
		},
		{
			name:     "complex: NOT with nested conditions",
			filter:   `not (userType eq "Contractor" or active eq false)`,
			wantSQL:  "NOT (((attributes->>'userType') = ? OR (attributes->>'active')::boolean = ?))",
			wantArgs: []any{"Contractor", false},
		},
		{
			name:     "complex: three-way AND",
			filter:   `active eq true and userType eq "Employee" and locale eq "en_US"`,
			wantSQL:  "(((attributes->>'active')::boolean = ? AND (attributes->>'userType') = ?) AND (attributes->>'locale') = ?)",
			wantArgs: []any{true, "Employee", "en_US"},
		},
		{
			name:     "complex: three-way OR",
			filter:   `title co "Engineer" or title co "Developer" or title co "Architect"`,
			wantSQL:  "(((attributes->>'title') ILIKE ? OR (attributes->>'title') ILIKE ?) OR (attributes->>'title') ILIKE ?)",
			wantArgs: []any{"%Engineer%", "%Developer%", "%Architect%"},
		},
		{
			name:     "complex: mixed operators on same attribute",
			filter:   `userName sw "john" and userName ew "@example.com"`,
			wantSQL:  "(email ILIKE ? AND email ILIKE ?)",
			wantArgs: []any{"john%", "%@example.com"},
		},
		{
			name:     "complex: deeply nested",
			filter:   `(active eq true and (userType eq "Employee" or userType eq "Contractor")) and (timezone eq "America/New_York" or timezone eq "America/Los_Angeles")`,
			wantSQL:  "(((attributes->>'active')::boolean = ? AND ((attributes->>'userType') = ? OR (attributes->>'userType') = ?)) AND ((attributes->>'timezone') = ? OR (attributes->>'timezone') = ?))",
			wantArgs: []any{true, "Employee", "Contractor", "America/New_York", "America/Los_Angeles"},
		},
		{
			name:     "complex: name parts with active status",
			filter:   `name.givenName sw "J" and name.familyName sw "D" and active eq true`,
			wantSQL:  "(((attributes->'name'->>'givenName') ILIKE ? AND (attributes->'name'->>'familyName') ILIKE ?) AND (attributes->>'active')::boolean = ?)",
			wantArgs: []any{"J%", "D%", true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseToSquirrel(tt.filter, ResourceTypeUser)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tt.wantSQL == "" {
				assert.Nil(t, result.Where)
				return
			}

			sql, args, err := result.Where.ToSql()
			require.NoError(t, err)
			assert.Equal(t, tt.wantSQL, sql)
			assert.Equal(t, tt.wantArgs, args)
		})
	}
}

func TestParseToSquirrel_GroupFilters(t *testing.T) {
	tests := []struct {
		name     string
		filter   string
		wantSQL  string
		wantArgs []any
	}{
		{
			name:     "displayName eq",
			filter:   `displayName eq "Engineering"`,
			wantSQL:  "display_name = ?",
			wantArgs: []any{"Engineering"},
		},
		{
			name:     "displayName co",
			filter:   `displayName co "Admin"`,
			wantSQL:  "display_name ILIKE ?",
			wantArgs: []any{"%Admin%"},
		},
		{
			name:     "displayName sw",
			filter:   `displayName sw "Dev"`,
			wantSQL:  "display_name ILIKE ?",
			wantArgs: []any{"Dev%"},
		},
		{
			name:     "displayName ne",
			filter:   `displayName ne "Deprecated"`,
			wantSQL:  "display_name <> ?",
			wantArgs: []any{"Deprecated"},
		},
		// externalId (indexed)
		{
			name:     "externalId eq",
			filter:   `externalId eq "group-ext-123"`,
			wantSQL:  "(attributes->>'externalId') = ?",
			wantArgs: []any{"group-ext-123"},
		},
		{
			name:     "externalId co",
			filter:   `externalId co "ext"`,
			wantSQL:  "(attributes->>'externalId') ILIKE ?",
			wantArgs: []any{"%ext%"},
		},
		// Combined filter
		{
			name:     "displayName and externalId",
			filter:   `displayName eq "Engineering" and externalId eq "eng-001"`,
			wantSQL:  "(display_name = ? AND (attributes->>'externalId') = ?)",
			wantArgs: []any{"Engineering", "eng-001"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseToSquirrel(tt.filter, ResourceTypeGroup)
			require.NoError(t, err)

			sql, args, err := result.Where.ToSql()
			require.NoError(t, err)
			assert.Equal(t, tt.wantSQL, sql)
			assert.Equal(t, tt.wantArgs, args)
		})
	}
}

func TestParseToSquirrel_SQLInjectionPrevention(t *testing.T) {
	tests := []struct {
		name   string
		filter string
	}{
		{
			name:   "SQL injection in attribute name",
			filter: `foo'); DROP TABLE users;-- eq "bar"`,
		},
		{
			name:   "SQL injection with semicolon",
			filter: `user;DELETE eq "test"`,
		},
		{
			name:   "SQL injection with quotes",
			filter: `user'name eq "test"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseToSquirrel(tt.filter, ResourceTypeUser)
			// Should either fail to parse OR fail validation
			if err == nil && result.Where != nil {
				_, _, sqlErr := result.Where.ToSql()
				if sqlErr == nil {
					t.Errorf("Expected error for injection attempt")
				}
			}
		})
	}
}

func TestParseToSquirrel_InvalidFilters(t *testing.T) {
	tests := []struct {
		name        string
		filter      string
		resourceTyp ResourceType
		wantErr     bool
		errContains string
	}{
		// SQL injection attempts - these should fail at parse or validation
		{
			name:        "SQL injection DROP TABLE in attribute",
			filter:      `foo'); DROP TABLE scim_users;-- eq "bar"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "SQL injection in sub-attribute",
			filter:      `name.foo'; DROP TABLE users;-- eq "bar"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "SQL injection with OR 1=1",
			filter:      `userName eq "x" or "1"="1"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "SQL injection hex encoding",
			filter:      `0x75736572 eq "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		// Invalid attribute names
		{
			name:        "attribute with special chars - parentheses",
			filter:      `user(name) eq "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "attribute with special chars - brackets",
			filter:      `user[0] eq "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "attribute with special chars - asterisk",
			filter:      `user* eq "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "attribute starting with number",
			filter:      `123user eq "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "empty attribute name",
			filter:      ` eq "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		// Invalid operators
		{
			name:        "invalid operator",
			filter:      `userName like "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "SQL LIKE operator attempt",
			filter:      `userName LIKE "%admin%"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		// Malformed filters
		{
			name:        "missing operator",
			filter:      `userName "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "unclosed parentheses",
			filter:      `(userName eq "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "double operators",
			filter:      `userName eq eq "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		// Boolean attribute edge cases
		{
			name:        "active with invalid boolean",
			filter:      `active eq "yes"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		{
			name:        "active with number",
			filter:      `active eq 1`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		// Nested attribute edge cases
		{
			name:        "deeply nested attribute (3 levels)",
			filter:      `name.formatted.value eq "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		// Path traversal attempts
		{
			name:        "path traversal in attribute",
			filter:      `../../../etc/passwd eq "test"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     true,
		},
		// XSS attempts (should be safely parameterized but test anyway)
		{
			name:        "XSS in value - script tag",
			filter:      `userName eq "<script>alert(1)</script>"`,
			resourceTyp: ResourceTypeUser,
			wantErr:     false, // Value is parameterized, so this should pass
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseToSquirrel(tt.filter, tt.resourceTyp)

			if tt.wantErr {
				// Should either fail to parse OR fail validation
				if err == nil && result.Where != nil {
					_, _, sqlErr := result.Where.ToSql()
					if sqlErr == nil {
						t.Errorf("Expected error for invalid filter %q but got none", tt.filter)
					}
				}
				if tt.errContains != "" && err != nil {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				if result.Where != nil {
					_, _, sqlErr := result.Where.ToSql()
					require.NoError(t, sqlErr)
				}
			}
		})
	}
}

func TestParseToSquirrel_ValuesSafelyParameterized(t *testing.T) {
	// These tests verify that dangerous values are safely parameterized
	// and not directly interpolated into SQL
	tests := []struct {
		name     string
		filter   string
		wantSQL  string
		wantArgs []any
	}{
		{
			name:     "value with SQL keywords",
			filter:   `userName eq "DROP TABLE users"`,
			wantSQL:  "email = ?",
			wantArgs: []any{"DROP TABLE users"},
		},
		{
			name:     "value with semicolon",
			filter:   `userName eq "test; DELETE FROM users"`,
			wantSQL:  "email = ?",
			wantArgs: []any{"test; DELETE FROM users"},
		},
		{
			name:     "value with single quotes",
			filter:   `userName eq "test'--"`,
			wantSQL:  "email = ?",
			wantArgs: []any{"test'--"},
		},
		{
			name:     "value with backslash",
			filter:   `userName eq "test\\n"`,
			wantSQL:  "email = ?",
			wantArgs: []any{"test\\\\n"}, // backslash is escaped by the parser
		},
		{
			name:     "value with percent (LIKE wildcard)",
			filter:   `userName eq "%admin%"`,
			wantSQL:  "email = ?",
			wantArgs: []any{"%admin%"},
		},
		{
			name:     "value with underscore (LIKE wildcard)",
			filter:   `userName eq "a_min"`,
			wantSQL:  "email = ?",
			wantArgs: []any{"a_min"},
		},
		{
			name:     "contains with LIKE wildcards in value - escaped",
			filter:   `userName co "50%"`,
			wantSQL:  "email ILIKE ?",
			wantArgs: []any{"%50\\%%"}, // % should be escaped in LIKE patterns
		},
		{
			name:     "contains with underscore in value - escaped",
			filter:   `userName co "user_name"`,
			wantSQL:  "email ILIKE ?",
			wantArgs: []any{"%user\\_name%"}, // _ should be escaped in LIKE patterns
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseToSquirrel(tt.filter, ResourceTypeUser)
			require.NoError(t, err)

			sql, args, err := result.Where.ToSql()
			require.NoError(t, err)
			assert.Equal(t, tt.wantSQL, sql)
			assert.Equal(t, tt.wantArgs, args)
		})
	}
}

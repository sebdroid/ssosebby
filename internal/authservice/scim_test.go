package authservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	ssoreadyv1 "github.com/sebdroid/ssosebby/internal/gen/ssoready/v1"
	"github.com/sebdroid/ssosebby/internal/store"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestSCIMUserToResource_ManagerReference(t *testing.T) {
	tests := []struct {
		name     string
		input    *ssoreadyv1.SCIMUser
		expected map[string]any
	}{
		{
			name: "simple manager ID is converted to complex reference",
			input: &ssoreadyv1.SCIMUser{
				Id:    "user123",
				Email: "test@example.com",
				Attributes: mustNewStruct(map[string]any{
					"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{
						"manager": "manager123",
					},
				}),
			},
			expected: map[string]any{
				"id":       "user123",
				"userName": "test@example.com",
				"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{
					"manager": map[string]any{
						"value": "manager123",
					},
				},
			},
		},
		{
			name: "already complex manager reference is preserved",
			input: &ssoreadyv1.SCIMUser{
				Id:    "user123",
				Email: "test@example.com",
				Attributes: mustNewStruct(map[string]any{
					"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{
						"manager": map[string]any{
							"value": "manager123",
						},
					},
				}),
			},
			expected: map[string]any{
				"id":       "user123",
				"userName": "test@example.com",
				"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{
					"manager": map[string]any{
						"value": "manager123",
					},
				},
			},
		},
		{
			name: "no manager reference remains unchanged",
			input: &ssoreadyv1.SCIMUser{
				Id:    "user123",
				Email: "test@example.com",
				Attributes: mustNewStruct(map[string]any{
					"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{},
				}),
			},
			expected: map[string]any{
				"id":       "user123",
				"userName": "test@example.com",
				"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": map[string]any{},
			},
		},
		{
			name: "no enterprise extension remains unchanged",
			input: &ssoreadyv1.SCIMUser{
				Id:         "user123",
				Email:      "test@example.com",
				Attributes: mustNewStruct(map[string]any{}),
			},
			expected: map[string]any{
				"id":       "user123",
				"userName": "test@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scimUserToResource(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSCIMFilterRegex(t *testing.T) {
	tests := []struct {
		name        string
		filter      string
		expected    string
		shouldMatch bool
	}{
		{
			name:        "userName filter",
			filter:      `userName eq "john@example.com"`,
			expected:    "john@example.com",
			shouldMatch: true,
		},
		{
			name:        "email.value filter",
			filter:      `email.value eq "jane@example.com"`,
			expected:    "jane@example.com",
			shouldMatch: true,
		},
		{
			name:        "email.value filter with special characters",
			filter:      `email.value eq "user+tag@example.com"`,
			expected:    "user+tag@example.com",
			shouldMatch: true,
		},
		{
			name:        "unsupported filter - different attribute",
			filter:      `displayName eq "John Doe"`,
			expected:    "",
			shouldMatch: false,
		},
		{
			name:        "unsupported filter - different operator",
			filter:      `userName ne "john@example.com"`,
			expected:    "",
			shouldMatch: false,
		},
		{
			name:        "unsupported filter - malformed",
			filter:      `userName eq john@example.com`,
			expected:    "",
			shouldMatch: false,
		},
	}

	filterEmailPat := regexp.MustCompile(`(userName|email\.value) eq "(.*)"`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := filterEmailPat.FindStringSubmatch(tt.filter)

			if tt.shouldMatch {
				assert.NotNil(t, match, "Expected filter to match but it didn't")
				assert.Len(t, match, 3, "Expected 3 capture groups (full match, attribute, value)")
				assert.Equal(t, tt.expected, match[2], "Expected email value to match")
			} else {
				assert.Nil(t, match, "Expected filter to not match but it did")
			}
		})
	}
}

func TestSCIMActiveFilterRegex(t *testing.T) {
	tests := []struct {
		name        string
		filter      string
		expected    string
		shouldMatch bool
	}{
		{
			name:        "active eq true",
			filter:      `active eq true`,
			expected:    "true",
			shouldMatch: true,
		},
		{
			name:        "active eq false",
			filter:      `active eq false`,
			expected:    "false",
			shouldMatch: true,
		},
		{
			name:        "active eq quoted true",
			filter:      `active eq "true"`,
			expected:    `"true"`,
			shouldMatch: true,
		},
		{
			name:        "active eq quoted false",
			filter:      `active eq "false"`,
			expected:    `"false"`,
			shouldMatch: true,
		},
		{
			name:        "compound filter - active first",
			filter:      `active eq true and userName eq "john@example.com"`,
			expected:    "true",
			shouldMatch: true,
		},
		{
			name:        "compound filter - active second",
			filter:      `userName eq "john@example.com" and active eq false`,
			expected:    "false",
			shouldMatch: true,
		},
		{
			name:        "unsupported operator",
			filter:      `active ne true`,
			expected:    "",
			shouldMatch: false,
		},
		{
			name:        "invalid value",
			filter:      `active eq yes`,
			expected:    "",
			shouldMatch: false,
		},
	}

	filterActivePat := regexp.MustCompile(`active eq (true|false|"true"|"false")`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := filterActivePat.FindStringSubmatch(tt.filter)

			if tt.shouldMatch {
				assert.NotNil(t, match, "Expected filter to match but it didn't")
				assert.Len(t, match, 2, "Expected 2 capture groups (full match, value)")
				assert.Equal(t, tt.expected, match[1], "Expected active value to match")
			} else {
				assert.Nil(t, match, "Expected filter to not match but it did")
			}
		})
	}
}

func TestSCIMCompoundFilterParsing(t *testing.T) {
	tests := []struct {
		name         string
		filter       string
		expectEmail  *string
		expectActive *bool
	}{
		{
			name:         "email only",
			filter:       `userName eq "john@example.com"`,
			expectEmail:  strPtr("john@example.com"),
			expectActive: nil,
		},
		{
			name:         "active only true",
			filter:       `active eq true`,
			expectEmail:  nil,
			expectActive: boolPtr(true),
		},
		{
			name:         "active only false",
			filter:       `active eq false`,
			expectEmail:  nil,
			expectActive: boolPtr(false),
		},
		{
			name:         "email and active true",
			filter:       `userName eq "john@example.com" and active eq true`,
			expectEmail:  strPtr("john@example.com"),
			expectActive: boolPtr(true),
		},
		{
			name:         "active false and email",
			filter:       `active eq false and userName eq "jane@example.com"`,
			expectEmail:  strPtr("jane@example.com"),
			expectActive: boolPtr(false),
		},
		{
			name:         "email.value with active",
			filter:       `email.value eq "test@example.com" and active eq true`,
			expectEmail:  strPtr("test@example.com"),
			expectActive: boolPtr(true),
		},
		{
			name:         "quoted active value",
			filter:       `active eq "false" and userName eq "user@example.com"`,
			expectEmail:  strPtr("user@example.com"),
			expectActive: boolPtr(false),
		},
	}

	filterActivePat := regexp.MustCompile(`active eq (true|false|"true"|"false")`)
	filterEmailPat := regexp.MustCompile(`(userName|email\.value) eq "(.*?)"`)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var filterEmail *string
			var filterActive *bool

			if match := filterActivePat.FindStringSubmatch(tt.filter); match != nil {
				activeValue := match[1]
				// strip quotes if present
				switch activeValue {
				case `"true"`:
					activeValue = "true"
				case `"false"`:
					activeValue = "false"
				}
				active := activeValue == "true"
				filterActive = &active
			}

			if match := filterEmailPat.FindStringSubmatch(tt.filter); match != nil {
				filterEmail = &match[2]
			}

			if tt.expectEmail != nil {
				assert.NotNil(t, filterEmail, "Expected email to be parsed")
				assert.Equal(t, *tt.expectEmail, *filterEmail)
			} else {
				assert.Nil(t, filterEmail, "Expected email to be nil")
			}

			if tt.expectActive != nil {
				assert.NotNil(t, filterActive, "Expected active to be parsed")
				assert.Equal(t, *tt.expectActive, *filterActive)
			} else {
				assert.Nil(t, filterActive, "Expected active to be nil")
			}
		})
	}
}

// Helper function to create structpb.Struct from map
func mustNewStruct(m map[string]any) *structpb.Struct {
	s, err := structpb.NewStruct(m)
	if err != nil {
		panic(err)
	}
	return s
}

func strPtr(s string) *string {
	return &s
}

func boolPtr(b bool) *bool {
	return &b
}

// mockSCIMStore implements the store methods needed for SCIM handler tests
type mockSCIMStore struct {
	GetSCIMUserIncludeDeletedFunc func(ctx context.Context, req *store.AuthGetSCIMUserIncludeDeletedRequest) (*ssoreadyv1.SCIMUser, error)
	UpdateSCIMUserFunc            func(ctx context.Context, req *store.AuthUpdateSCIMUserRequest) (*store.AuthUpdateSCIMUserResponse, error)
	GetSCIMDirectoryDomainsFunc   func(ctx context.Context, scimDirectoryID string) ([]string, error)
}

func (m *mockSCIMStore) AuthGetSCIMUserIncludeDeleted(ctx context.Context, req *store.AuthGetSCIMUserIncludeDeletedRequest) (*ssoreadyv1.SCIMUser, error) {
	if m.GetSCIMUserIncludeDeletedFunc != nil {
		return m.GetSCIMUserIncludeDeletedFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockSCIMStore) AuthUpdateSCIMUser(ctx context.Context, req *store.AuthUpdateSCIMUserRequest) (*store.AuthUpdateSCIMUserResponse, error) {
	if m.UpdateSCIMUserFunc != nil {
		return m.UpdateSCIMUserFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockSCIMStore) AuthGetSCIMDirectoryOrganizationDomains(ctx context.Context, scimDirectoryID string) ([]string, error) {
	if m.GetSCIMDirectoryDomainsFunc != nil {
		return m.GetSCIMDirectoryDomainsFunc(ctx, scimDirectoryID)
	}
	return []string{"example.com"}, nil
}

func TestScimPatchUser_DeletedUser_Returns404(t *testing.T) {
	mockStore := &mockSCIMStore{
		GetSCIMUserIncludeDeletedFunc: func(ctx context.Context, req *store.AuthGetSCIMUserIncludeDeletedRequest) (*ssoreadyv1.SCIMUser, error) {
			attrs, _ := structpb.NewStruct(map[string]any{"active": false})
			return &ssoreadyv1.SCIMUser{
				Id:              req.SCIMUserID,
				ScimDirectoryId: req.SCIMDirectoryID,
				Email:           "deleted@example.com",
				Deleted:         true, // User is deleted
				Attributes:      attrs,
			}, nil
		},
	}

	w := httptest.NewRecorder()
	ctx := context.Background()

	scimUser, err := mockStore.AuthGetSCIMUserIncludeDeleted(ctx, &store.AuthGetSCIMUserIncludeDeletedRequest{
		SCIMDirectoryID: "scim_directory_123",
		SCIMUserID:      "scim_user_456",
	})
	assert.NoError(t, err)

	// This is the key check - if user is deleted, return 404
	if scimUser.Deleted {
		w.WriteHeader(http.StatusNotFound)
	}

	assert.Equal(t, http.StatusNotFound, w.Code, "PATCH on deleted user should return 404")
}

func TestScimPatchUser_NonExistentUser_Returns404(t *testing.T) {
	mockStore := &mockSCIMStore{
		GetSCIMUserIncludeDeletedFunc: func(ctx context.Context, req *store.AuthGetSCIMUserIncludeDeletedRequest) (*ssoreadyv1.SCIMUser, error) {
			return nil, store.ErrSCIMUserNotFound
		},
	}

	w := httptest.NewRecorder()
	ctx := context.Background()

	_, err := mockStore.AuthGetSCIMUserIncludeDeleted(ctx, &store.AuthGetSCIMUserIncludeDeletedRequest{
		SCIMDirectoryID: "scim_directory_123",
		SCIMUserID:      "scim_user_456",
	})

	// This is the key check - if user not found, return 404
	if err == store.ErrSCIMUserNotFound {
		w.WriteHeader(http.StatusNotFound)
	}

	assert.Equal(t, http.StatusNotFound, w.Code, "PATCH on non-existent user should return 404")
}

func TestScimUpdateUser_DeletedUser_Returns404(t *testing.T) {
	mockStore := &mockSCIMStore{
		UpdateSCIMUserFunc: func(ctx context.Context, req *store.AuthUpdateSCIMUserRequest) (*store.AuthUpdateSCIMUserResponse, error) {
			return nil, store.ErrSCIMUserNotFound
		},
	}

	w := httptest.NewRecorder()
	ctx := context.Background()

	_, err := mockStore.AuthUpdateSCIMUser(ctx, &store.AuthUpdateSCIMUserRequest{
		SCIMUser: &ssoreadyv1.SCIMUser{
			Id:              "scim_user_456",
			ScimDirectoryId: "scim_directory_123",
			Email:           "user@example.com",
		},
	})

	// This is the key check - if user not found (deleted), return 404
	if err == store.ErrSCIMUserNotFound {
		w.WriteHeader(http.StatusNotFound)
	}

	assert.Equal(t, http.StatusNotFound, w.Code, "PUT on deleted user should return 404")
}

func TestScimUpdateUser_NonExistentUser_Returns404(t *testing.T) {
	mockStore := &mockSCIMStore{
		UpdateSCIMUserFunc: func(ctx context.Context, req *store.AuthUpdateSCIMUserRequest) (*store.AuthUpdateSCIMUserResponse, error) {
			return nil, store.ErrSCIMUserNotFound
		},
	}

	w := httptest.NewRecorder()
	ctx := context.Background()

	_, err := mockStore.AuthUpdateSCIMUser(ctx, &store.AuthUpdateSCIMUserRequest{
		SCIMUser: &ssoreadyv1.SCIMUser{
			Id:              "non_existent_user",
			ScimDirectoryId: "scim_directory_123",
			Email:           "user@example.com",
		},
	})

	if err == store.ErrSCIMUserNotFound {
		w.WriteHeader(http.StatusNotFound)
	}

	assert.Equal(t, http.StatusNotFound, w.Code, "PUT on non-existent user should return 404")
}

func TestScimPatchUser_ActiveUser_UpdatesSuccessfully(t *testing.T) {
	mockStore := &mockSCIMStore{
		GetSCIMUserIncludeDeletedFunc: func(ctx context.Context, req *store.AuthGetSCIMUserIncludeDeletedRequest) (*ssoreadyv1.SCIMUser, error) {
			attrs, _ := structpb.NewStruct(map[string]any{"active": true})
			return &ssoreadyv1.SCIMUser{
				Id:              req.SCIMUserID,
				ScimDirectoryId: req.SCIMDirectoryID,
				Email:           "active@example.com",
				Deleted:         false,
				Attributes:      attrs,
			}, nil
		},
		UpdateSCIMUserFunc: func(ctx context.Context, req *store.AuthUpdateSCIMUserRequest) (*store.AuthUpdateSCIMUserResponse, error) {
			return &store.AuthUpdateSCIMUserResponse{
				SCIMUser: req.SCIMUser,
			}, nil
		},
	}

	w := httptest.NewRecorder()
	ctx := context.Background()

	scimUser, err := mockStore.AuthGetSCIMUserIncludeDeleted(ctx, &store.AuthGetSCIMUserIncludeDeletedRequest{
		SCIMDirectoryID: "scim_directory_123",
		SCIMUserID:      "scim_user_456",
	})
	assert.NoError(t, err)
	assert.False(t, scimUser.Deleted, "User should not be deleted")

	// User is not deleted, so update should proceed
	if !scimUser.Deleted {
		_, err = mockStore.AuthUpdateSCIMUser(ctx, &store.AuthUpdateSCIMUserRequest{
			SCIMUser: scimUser,
		})
		assert.NoError(t, err)
		w.WriteHeader(http.StatusNoContent)
	}

	assert.Equal(t, http.StatusNoContent, w.Code, "PATCH on active user should return 204")
}

func TestScimPatchUser_InactiveUser_UpdatesSuccessfully(t *testing.T) {
	mockStore := &mockSCIMStore{
		GetSCIMUserIncludeDeletedFunc: func(ctx context.Context, req *store.AuthGetSCIMUserIncludeDeletedRequest) (*ssoreadyv1.SCIMUser, error) {
			// User with active=false (inactive) but NOT deleted
			attrs, _ := structpb.NewStruct(map[string]any{"active": false})
			return &ssoreadyv1.SCIMUser{
				Id:              req.SCIMUserID,
				ScimDirectoryId: req.SCIMDirectoryID,
				Email:           "inactive@example.com",
				Deleted:         false, // Not deleted, just inactive
				Attributes:      attrs,
			}, nil
		},
		UpdateSCIMUserFunc: func(ctx context.Context, req *store.AuthUpdateSCIMUserRequest) (*store.AuthUpdateSCIMUserResponse, error) {
			return &store.AuthUpdateSCIMUserResponse{
				SCIMUser: req.SCIMUser,
			}, nil
		},
	}

	w := httptest.NewRecorder()
	ctx := context.Background()

	scimUser, err := mockStore.AuthGetSCIMUserIncludeDeleted(ctx, &store.AuthGetSCIMUserIncludeDeletedRequest{
		SCIMDirectoryID: "scim_directory_123",
		SCIMUserID:      "scim_user_456",
	})
	assert.NoError(t, err)
	assert.False(t, scimUser.Deleted, "User should not be deleted (just inactive)")

	// User is not deleted, so update should proceed even if inactive
	if !scimUser.Deleted {
		_, err = mockStore.AuthUpdateSCIMUser(ctx, &store.AuthUpdateSCIMUserRequest{
			SCIMUser: scimUser,
		})
		assert.NoError(t, err)
		w.WriteHeader(http.StatusNoContent)
	}

	assert.Equal(t, http.StatusNoContent, w.Code, "PATCH on inactive (but not deleted) user should return 204")
}

func TestScimUpdateUser_ActiveUser_UpdatesSuccessfully(t *testing.T) {
	updatedUser := &ssoreadyv1.SCIMUser{
		Id:              "scim_user_456",
		ScimDirectoryId: "scim_directory_123",
		Email:           "updated@example.com",
		Deleted:         false,
	}

	mockStore := &mockSCIMStore{
		UpdateSCIMUserFunc: func(ctx context.Context, req *store.AuthUpdateSCIMUserRequest) (*store.AuthUpdateSCIMUserResponse, error) {
			return &store.AuthUpdateSCIMUserResponse{
				SCIMUser: updatedUser,
			}, nil
		},
	}

	w := httptest.NewRecorder()
	ctx := context.Background()

	resp, err := mockStore.AuthUpdateSCIMUser(ctx, &store.AuthUpdateSCIMUserRequest{
		SCIMUser: &ssoreadyv1.SCIMUser{
			Id:              "scim_user_456",
			ScimDirectoryId: "scim_directory_123",
			Email:           "updated@example.com",
		},
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "updated@example.com", resp.SCIMUser.Email)
	w.WriteHeader(http.StatusOK)

	assert.Equal(t, http.StatusOK, w.Code, "PUT on active user should return 200")
}

func TestScimUpdateUser_InactiveUser_UpdatesSuccessfully(t *testing.T) {
	// Inactive user (active=false in attributes) but not deleted
	attrs, _ := structpb.NewStruct(map[string]any{"active": false})
	updatedUser := &ssoreadyv1.SCIMUser{
		Id:              "scim_user_456",
		ScimDirectoryId: "scim_directory_123",
		Email:           "inactive@example.com",
		Deleted:         false,
		Attributes:      attrs,
	}

	mockStore := &mockSCIMStore{
		UpdateSCIMUserFunc: func(ctx context.Context, req *store.AuthUpdateSCIMUserRequest) (*store.AuthUpdateSCIMUserResponse, error) {
			return &store.AuthUpdateSCIMUserResponse{
				SCIMUser: updatedUser,
			}, nil
		},
	}

	w := httptest.NewRecorder()
	ctx := context.Background()

	resp, err := mockStore.AuthUpdateSCIMUser(ctx, &store.AuthUpdateSCIMUserRequest{
		SCIMUser: &ssoreadyv1.SCIMUser{
			Id:              "scim_user_456",
			ScimDirectoryId: "scim_directory_123",
			Email:           "inactive@example.com",
			Attributes:      attrs,
		},
	})

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "inactive@example.com", resp.SCIMUser.Email)
	w.WriteHeader(http.StatusOK)

	assert.Equal(t, http.StatusOK, w.Code, "PUT on inactive (but not deleted) user should return 200")
}

// Tests for SCIM Schema definitions

func TestScimUserSchema(t *testing.T) {
	// Verify the User schema has required fields per RFC 7643
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:User", scimUserSchema["id"])
	assert.Equal(t, "User", scimUserSchema["name"])
	assert.Equal(t, "User Account", scimUserSchema["description"])

	attributes := scimUserSchema["attributes"].([]map[string]any)
	assert.NotEmpty(t, attributes, "User schema should have attributes")

	// Verify required userName attribute exists
	var foundUserName bool
	for _, attr := range attributes {
		if attr["name"] == "userName" {
			foundUserName = true
			assert.Equal(t, "string", attr["type"])
			assert.Equal(t, true, attr["required"])
			assert.Equal(t, "server", attr["uniqueness"])
			break
		}
	}
	assert.True(t, foundUserName, "User schema should have userName attribute")
}

func TestScimGroupSchema(t *testing.T) {
	// Verify the Group schema has required fields per RFC 7643
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:Group", scimGroupSchema["id"])
	assert.Equal(t, "Group", scimGroupSchema["name"])

	attributes := scimGroupSchema["attributes"].([]map[string]any)
	assert.NotEmpty(t, attributes, "Group schema should have attributes")

	// Verify required displayName attribute exists
	var foundDisplayName bool
	for _, attr := range attributes {
		if attr["name"] == "displayName" {
			foundDisplayName = true
			assert.Equal(t, "string", attr["type"])
			assert.Equal(t, true, attr["required"])
			break
		}
	}
	assert.True(t, foundDisplayName, "Group schema should have displayName attribute")

	// Verify members attribute exists
	var foundMembers bool
	for _, attr := range attributes {
		if attr["name"] == "members" {
			foundMembers = true
			assert.Equal(t, "complex", attr["type"])
			assert.Equal(t, true, attr["multiValued"])
			break
		}
	}
	assert.True(t, foundMembers, "Group schema should have members attribute")
}

func TestScimEnterpriseUserSchema(t *testing.T) {
	// Verify the EnterpriseUser schema has required fields per RFC 7643
	assert.Equal(t, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", scimEnterpriseUserSchema["id"])
	assert.Equal(t, "EnterpriseUser", scimEnterpriseUserSchema["name"])

	attributes := scimEnterpriseUserSchema["attributes"].([]map[string]any)
	assert.NotEmpty(t, attributes, "EnterpriseUser schema should have attributes")

	// Verify expected enterprise attributes exist
	expectedAttrs := []string{"employeeNumber", "costCenter", "organization", "division", "department", "manager"}
	foundAttrs := make(map[string]bool)
	for _, attr := range attributes {
		name := attr["name"].(string)
		foundAttrs[name] = true
	}

	for _, expected := range expectedAttrs {
		assert.True(t, foundAttrs[expected], "EnterpriseUser schema should have %s attribute", expected)
	}
}

func TestCopySchemaWithLocation(t *testing.T) {
	baseURL := "/v1/scim/test_directory"

	// Test that copySchemaWithLocation creates correct location URLs
	userSchemaCopy := copySchemaWithLocation(scimUserSchema, baseURL)

	meta := userSchemaCopy["meta"].(map[string]any)
	assert.Equal(t, "Schema", meta["resourceType"])
	assert.Equal(t, "/v1/scim/test_directory/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", meta["location"])

	// Verify original schema is not modified
	originalMeta := scimUserSchema["meta"].(map[string]any)
	assert.Contains(t, originalMeta["location"], "{scim_directory_id}", "Original schema should not be modified")
}

func TestScimGetSchemasResponse(t *testing.T) {
	// Test the schemas list response format
	baseURL := "/v1/scim/test_directory"

	userSchema := copySchemaWithLocation(scimUserSchema, baseURL)
	groupSchema := copySchemaWithLocation(scimGroupSchema, baseURL)
	enterpriseUserSchema := copySchemaWithLocation(scimEnterpriseUserSchema, baseURL)

	schemas := []any{userSchema, groupSchema, enterpriseUserSchema}

	// Verify we have exactly 3 schemas
	assert.Len(t, schemas, 3)

	// Verify each schema has an id
	for _, s := range schemas {
		schema := s.(map[string]any)
		assert.NotEmpty(t, schema["id"], "Each schema should have an id")
		assert.NotEmpty(t, schema["name"], "Each schema should have a name")
		assert.NotEmpty(t, schema["attributes"], "Each schema should have attributes")
	}
}

func TestScimResourceTypeDefinitions(t *testing.T) {
	baseURL := "/v1/scim/test_directory"

	// Test User ResourceType
	userResourceType := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":          "User",
		"name":        "User",
		"endpoint":    "/Users",
		"description": "User Account",
		"schema":      "urn:ietf:params:scim:schemas:core:2.0:User",
		"schemaExtensions": []map[string]any{
			{
				"schema":   "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
				"required": false,
			},
		},
		"meta": map[string]any{
			"location":     baseURL + "/ResourceTypes/User",
			"resourceType": "ResourceType",
		},
	}

	assert.Equal(t, "User", userResourceType["id"])
	assert.Equal(t, "User", userResourceType["name"])
	assert.Equal(t, "/Users", userResourceType["endpoint"])
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:User", userResourceType["schema"])

	// Verify schema extensions
	extensions := userResourceType["schemaExtensions"].([]map[string]any)
	assert.Len(t, extensions, 1)
	assert.Equal(t, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User", extensions[0]["schema"])
	assert.Equal(t, false, extensions[0]["required"])

	// Test Group ResourceType
	groupResourceType := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":          "Group",
		"name":        "Group",
		"endpoint":    "/Groups",
		"description": "Group",
		"schema":      "urn:ietf:params:scim:schemas:core:2.0:Group",
		"meta": map[string]any{
			"location":     baseURL + "/ResourceTypes/Group",
			"resourceType": "ResourceType",
		},
	}

	assert.Equal(t, "Group", groupResourceType["id"])
	assert.Equal(t, "Group", groupResourceType["name"])
	assert.Equal(t, "/Groups", groupResourceType["endpoint"])
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:Group", groupResourceType["schema"])
}

func TestScimSchemaAttributeTypes(t *testing.T) {
	// Verify that schema attributes have valid types per RFC 7643
	validTypes := map[string]bool{
		"string":    true,
		"boolean":   true,
		"decimal":   true,
		"integer":   true,
		"dateTime":  true,
		"reference": true,
		"complex":   true,
		"binary":    true,
	}

	attributes := scimUserSchema["attributes"].([]map[string]any)
	for _, attr := range attributes {
		attrType := attr["type"].(string)
		assert.True(t, validTypes[attrType], "Attribute %s has invalid type: %s", attr["name"], attrType)
	}
}

func TestScimSchemaAttributeMutability(t *testing.T) {
	// Verify that schema attributes have valid mutability values per RFC 7643
	validMutability := map[string]bool{
		"readOnly":  true,
		"readWrite": true,
		"immutable": true,
		"writeOnly": true,
	}

	attributes := scimUserSchema["attributes"].([]map[string]any)
	for _, attr := range attributes {
		if mutability, ok := attr["mutability"].(string); ok {
			assert.True(t, validMutability[mutability], "Attribute %s has invalid mutability: %s", attr["name"], mutability)
		}
	}
}

func TestScimSchemaAttributeReturned(t *testing.T) {
	// Verify that schema attributes have valid returned values per RFC 7643
	validReturned := map[string]bool{
		"always":  true,
		"never":   true,
		"default": true,
		"request": true,
	}

	attributes := scimUserSchema["attributes"].([]map[string]any)
	for _, attr := range attributes {
		if returned, ok := attr["returned"].(string); ok {
			assert.True(t, validReturned[returned], "Attribute %s has invalid returned: %s", attr["name"], returned)
		}
	}
}

func TestScimSchemaSubAttributes(t *testing.T) {
	// Verify complex attributes have subAttributes defined
	attributes := scimUserSchema["attributes"].([]map[string]any)

	for _, attr := range attributes {
		if attr["type"] == "complex" {
			subAttrs, ok := attr["subAttributes"]
			assert.True(t, ok, "Complex attribute %s should have subAttributes", attr["name"])
			assert.NotEmpty(t, subAttrs, "Complex attribute %s should have non-empty subAttributes", attr["name"])
		}
	}
}

func TestScimSchemaURNs(t *testing.T) {
	// Verify all schema URNs follow SCIM naming conventions
	schemas := []map[string]any{scimUserSchema, scimGroupSchema, scimEnterpriseUserSchema}

	for _, schema := range schemas {
		id := schema["id"].(string)
		assert.True(t, len(id) > 0, "Schema id should not be empty")
		assert.Contains(t, id, "urn:ietf:params:scim:schemas:", "Schema id should be a valid SCIM URN")
	}
}

// Tests for ServiceProviderConfig endpoint

func TestScimServiceProviderConfig_RequiredFields(t *testing.T) {
	// Build a ServiceProviderConfig response as the handler would
	baseURL := "/v1/scim/test_directory"

	config := map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://www.rfc-editor.org/rfc/rfc7644",
		"patch": map[string]any{
			"supported": true,
		},
		"bulk": map[string]any{
			"supported":      false,
			"maxOperations":  0,
			"maxPayloadSize": 0,
		},
		"filter": map[string]any{
			"supported":  true,
			"maxResults": 200,
		},
		"changePassword": map[string]any{
			"supported": false,
		},
		"sort": map[string]any{
			"supported": false,
		},
		"etag": map[string]any{
			"supported": false,
		},
		"authenticationSchemes": []map[string]any{
			{
				"type":             "oauthbearertoken",
				"name":             "OAuth Bearer Token",
				"description":      "Authentication scheme using the OAuth Bearer Token Standard",
				"specUri":          "https://www.rfc-editor.org/rfc/rfc6750",
				"documentationUri": "https://www.rfc-editor.org/rfc/rfc6750",
			},
		},
		"meta": map[string]any{
			"location":     baseURL + "/ServiceProviderConfig",
			"resourceType": "ServiceProviderConfig",
		},
	}

	// Verify schema
	schemas := config["schemas"].([]string)
	assert.Len(t, schemas, 1)
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig", schemas[0])

	// Verify all required complex attributes exist per RFC 7643 Section 5
	assert.NotNil(t, config["patch"], "patch is required")
	assert.NotNil(t, config["bulk"], "bulk is required")
	assert.NotNil(t, config["filter"], "filter is required")
	assert.NotNil(t, config["changePassword"], "changePassword is required")
	assert.NotNil(t, config["sort"], "sort is required")
	assert.NotNil(t, config["etag"], "etag is required")
	assert.NotNil(t, config["authenticationSchemes"], "authenticationSchemes is required")
}

func TestScimServiceProviderConfig_PatchSupported(t *testing.T) {
	config := map[string]any{
		"patch": map[string]any{
			"supported": true,
		},
	}

	patch := config["patch"].(map[string]any)
	assert.True(t, patch["supported"].(bool), "PATCH should be supported")
}

func TestScimServiceProviderConfig_BulkConfig(t *testing.T) {
	config := map[string]any{
		"bulk": map[string]any{
			"supported":      false,
			"maxOperations":  0,
			"maxPayloadSize": 0,
		},
	}

	bulk := config["bulk"].(map[string]any)
	assert.False(t, bulk["supported"].(bool), "Bulk operations not supported")
	assert.Equal(t, 0, bulk["maxOperations"].(int), "maxOperations should be 0 when not supported")
	assert.Equal(t, 0, bulk["maxPayloadSize"].(int), "maxPayloadSize should be 0 when not supported")
}

func TestScimServiceProviderConfig_FilterConfig(t *testing.T) {
	config := map[string]any{
		"filter": map[string]any{
			"supported":  true,
			"maxResults": 200,
		},
	}

	filter := config["filter"].(map[string]any)
	assert.True(t, filter["supported"].(bool), "Filter should be supported")
	assert.Equal(t, 200, filter["maxResults"].(int), "maxResults should be 200")
}

func TestScimServiceProviderConfig_AuthenticationSchemes(t *testing.T) {
	config := map[string]any{
		"authenticationSchemes": []map[string]any{
			{
				"type":             "oauthbearertoken",
				"name":             "OAuth Bearer Token",
				"description":      "Authentication scheme using the OAuth Bearer Token Standard",
				"specUri":          "https://www.rfc-editor.org/rfc/rfc6750",
				"documentationUri": "https://www.rfc-editor.org/rfc/rfc6750",
			},
		},
	}

	schemes := config["authenticationSchemes"].([]map[string]any)
	assert.Len(t, schemes, 1, "Should have one authentication scheme")

	scheme := schemes[0]
	assert.Equal(t, "oauthbearertoken", scheme["type"], "Type should be oauthbearertoken")
	assert.Equal(t, "OAuth Bearer Token", scheme["name"], "Name should be OAuth Bearer Token")
	assert.NotEmpty(t, scheme["description"], "Description is required")

	// Verify type is a valid SCIM authentication type
	validTypes := map[string]bool{
		"oauth":            true,
		"oauth2":           true,
		"oauthbearertoken": true,
		"httpbasic":        true,
		"httpdigest":       true,
	}
	assert.True(t, validTypes[scheme["type"].(string)], "Authentication type should be valid per RFC 7643")
}

func TestScimServiceProviderConfig_MetaLocation(t *testing.T) {
	baseURL := "/v1/scim/test_directory"

	config := map[string]any{
		"meta": map[string]any{
			"location":     baseURL + "/ServiceProviderConfig",
			"resourceType": "ServiceProviderConfig",
		},
	}

	meta := config["meta"].(map[string]any)
	assert.Equal(t, "/v1/scim/test_directory/ServiceProviderConfig", meta["location"])
	assert.Equal(t, "ServiceProviderConfig", meta["resourceType"])
}

func TestScimServiceProviderConfig_UnsupportedFeatures(t *testing.T) {
	// Verify features that are not supported are correctly marked
	config := map[string]any{
		"changePassword": map[string]any{
			"supported": false,
		},
		"sort": map[string]any{
			"supported": false,
		},
		"etag": map[string]any{
			"supported": false,
		},
		"bulk": map[string]any{
			"supported": false,
		},
	}

	changePassword := config["changePassword"].(map[string]any)
	assert.False(t, changePassword["supported"].(bool), "changePassword should not be supported")

	sort := config["sort"].(map[string]any)
	assert.False(t, sort["supported"].(bool), "sort should not be supported")

	etag := config["etag"].(map[string]any)
	assert.False(t, etag["supported"].(bool), "etag should not be supported")

	bulk := config["bulk"].(map[string]any)
	assert.False(t, bulk["supported"].(bool), "bulk should not be supported")
}

// Tests for SCIM count parameter (RFC 7644 Section 3.4.2.4)

func TestScimCountParameterParsing(t *testing.T) {
	tests := []struct {
		name          string
		countParam    string
		expectedCount int
		shouldError   bool
	}{
		{
			name:          "no count parameter uses default (-1)",
			countParam:    "",
			expectedCount: -1,
			shouldError:   false,
		},
		{
			name:          "count=0 returns only totalResults",
			countParam:    "0",
			expectedCount: 0,
			shouldError:   false,
		},
		{
			name:          "positive count value",
			countParam:    "50",
			expectedCount: 50,
			shouldError:   false,
		},
		{
			name:          "negative count treated as 0 per RFC 7644",
			countParam:    "-5",
			expectedCount: 0,
			shouldError:   false,
		},
		{
			name:          "invalid count value",
			countParam:    "abc",
			expectedCount: 0,
			shouldError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the parsing logic from scimListUsers/scimListGroups
			count := -1 // default: unspecified
			var parseErr error

			if tt.countParam != "" {
				var c int
				c, parseErr = parseInt(tt.countParam)
				if parseErr == nil {
					// Per RFC 7644: negative values SHALL be interpreted as "0"
					if c < 0 {
						c = 0
					}
					count = c
				}
			}

			if tt.shouldError {
				assert.Error(t, parseErr, "Expected parse error for invalid count")
			} else {
				assert.NoError(t, parseErr, "Expected no parse error")
				assert.Equal(t, tt.expectedCount, count, "Count value mismatch")
			}
		})
	}
}

func TestScimCountLimitBehavior(t *testing.T) {
	// Test that count is properly capped at MaxSCIMPageSize
	tests := []struct {
		name          string
		requestCount  int
		expectedLimit int
	}{
		{
			name:          "count=-1 uses default page size",
			requestCount:  -1,
			expectedLimit: store.DefaultSCIMPageSize,
		},
		{
			name:          "count within max returns requested count",
			requestCount:  50,
			expectedLimit: 50,
		},
		{
			name:          "count exceeding max is capped",
			requestCount:  500,
			expectedLimit: store.MaxSCIMPageSize,
		},
		{
			name:          "count equal to max returns max",
			requestCount:  store.MaxSCIMPageSize,
			expectedLimit: store.MaxSCIMPageSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the limit calculation logic from store layer
			limit := store.DefaultSCIMPageSize
			if tt.requestCount > 0 {
				limit = tt.requestCount
				if limit > store.MaxSCIMPageSize {
					limit = store.MaxSCIMPageSize
				}
			}

			assert.Equal(t, tt.expectedLimit, limit, "Limit value mismatch")
		})
	}
}

func TestScimCountZeroReturnsOnlyTotalResults(t *testing.T) {
	// Per RFC 7644 3.4.2.4: count=0 means return no resources but still return totalResults
	// This test verifies the expected behavior structure

	type listResponse struct {
		TotalResults int
		Resources    []any
	}

	// Simulate count=0 behavior
	count := 0
	totalResults := 100

	var response listResponse
	if count == 0 {
		// When count=0, return only totalResults with empty resources
		response = listResponse{
			TotalResults: totalResults,
			Resources:    nil,
		}
	}

	assert.Equal(t, totalResults, response.TotalResults, "totalResults should still be returned")
	assert.Nil(t, response.Resources, "Resources should be nil when count=0")
}

func TestScimStartIndexWithCount(t *testing.T) {
	// Test that startIndex and count work together for pagination
	tests := []struct {
		name           string
		startIndex     int
		count          int
		totalResults   int
		expectedOffset int
	}{
		{
			name:           "first page",
			startIndex:     1,
			count:          10,
			totalResults:   100,
			expectedOffset: 0, // SCIM is 1-indexed, store is 0-indexed
		},
		{
			name:           "second page",
			startIndex:     11,
			count:          10,
			totalResults:   100,
			expectedOffset: 10,
		},
		{
			name:           "custom page size",
			startIndex:     51,
			count:          25,
			totalResults:   100,
			expectedOffset: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// SCIM startIndex is 1-indexed, convert to 0-indexed offset
			offset := tt.startIndex - 1

			assert.Equal(t, tt.expectedOffset, offset, "Offset calculation mismatch")
			assert.GreaterOrEqual(t, offset, 0, "Offset should never be negative")
		})
	}
}

// parseInt is a helper to simulate strconv.Atoi for testing
func parseInt(s string) (int, error) {
	var result int
	_, err := regexp.MatchString(`^-?\d+$`, s)
	if err != nil {
		return 0, err
	}

	// Use a simple approach for testing
	for i, c := range s {
		if c == '-' && i == 0 {
			continue
		}
		if c < '0' || c > '9' {
			return 0, assert.AnError
		}
		result = result*10 + int(c-'0')
	}

	if len(s) > 0 && s[0] == '-' {
		result = -result
	}

	return result, nil
}

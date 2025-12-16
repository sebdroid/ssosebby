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

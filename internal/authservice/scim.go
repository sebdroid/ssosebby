package authservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/sebdroid/ssosebby/internal/scimpatch"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gorilla/mux"
	"github.com/sebdroid/ssosebby/internal/emailaddr"
	ssoreadyv1 "github.com/sebdroid/ssosebby/internal/gen/ssoready/v1"
	"github.com/sebdroid/ssosebby/internal/store"
	"google.golang.org/protobuf/types/known/structpb"
)

type scimListResponse struct {
	TotalResults int      `json:"totalResults"`
	ItemsPerPage int      `json:"itemsPerPage"`
	StartIndex   int      `json:"startIndex"`
	Schemas      []string `json:"schemas"`
	Resources    []any    `json:"Resources"`
}

func (s *Service) scimListUsers(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return err
		}
		panic(err)
	}

	slog.InfoContext(ctx, "scim_list_users", "scim_directory_id", scimDirectoryID, "filter", r.URL.Query().Get("filter"))

	// parse startIndex early so it can be used by both filtered and unfiltered queries
	startIndex := 0
	if r.URL.Query().Get("startIndex") != "" {
		i, err := strconv.Atoi(r.URL.Query().Get("startIndex"))
		if err != nil {
			http.Error(w, fmt.Sprintf("parse startIndex: %s", err), http.StatusBadRequest)
			return nil
		}
		startIndex = i - 1 // scim is 1-indexed, store is 0-indexed
	}

	// parse count per RFC 7644 3.4.2.4
	// -1 means unspecified (use default), 0 means return only totalResults, negative values treated as 0
	count := -1 // default: unspecified, let store use default
	if r.URL.Query().Has("count") {
		c, err := strconv.Atoi(r.URL.Query().Get("count"))
		if err != nil {
			http.Error(w, fmt.Sprintf("parse count: %s", err), http.StatusBadRequest)
			return nil
		}
		// Per RFC 7644: negative values SHALL be interpreted as "0"
		if c < 0 {
			c = 0
		}
		count = c
	}

	// Use unified filter parsing - supports RFC 7644 compliant filters
	// including: eq, ne, co, sw, ew, pr, gt, lt, ge, le, and, or, not
	// Empty filter string is handled gracefully (returns all users)
	filter := r.URL.Query().Get("filter")
	scimUsers, err := s.Store.AuthListSCIMUsersFiltered(ctx, &store.AuthListSCIMUsersFilteredRequest{
		SCIMDirectoryID: scimDirectoryID,
		Filter:          filter,
		StartIndex:      startIndex,
		Count:           count,
	})
	if err != nil {
		if errors.Is(err, store.ErrInvalidSCIMFilter) {
			// Return SCIM-compliant error for invalid filter
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]any{
				"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"scimType": "invalidFilter",
				"detail":   err.Error(),
				"status":   400,
			}); err != nil {
				panic(err)
			}
			return nil
		}
		panic(fmt.Errorf("store: %w", err))
	}

	resources := []any{} // intentionally initialized to avoid returning `null` instead of `[]`
	for _, scimUser := range scimUsers.SCIMUsers {
		resources = append(resources, scimUserToResource(scimUser))
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(scimListResponse{
		TotalResults: scimUsers.TotalResults,
		ItemsPerPage: len(resources),
		StartIndex:   startIndex + 1, // convert back to 1-indexed for response
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		Resources:    resources,
	}); err != nil {
		panic(err)
	}
	return nil
}

func (s *Service) scimGetUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]
	scimUserID := mux.Vars(r)["scim_user_id"]

	scimUser, err := s.Store.AuthGetSCIMUser(ctx, &store.AuthGetSCIMUserRequest{
		SCIMDirectoryID: scimDirectoryID,
		SCIMUserID:      scimUserID,
	})
	if err != nil {
		if errors.Is(err, store.ErrSCIMUserNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return nil
		}

		return err
	}

	resource := scimUserToResource(scimUser)
	resource["schemas"] = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resource); err != nil {
		return err
	}
	return nil
}

func (s *Service) scimCreateUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]

	defer r.Body.Close()
	var resource map[string]any
	if err := json.NewDecoder(r.Body).Decode(&resource); err != nil {
		panic(err)
	}

	userName := resource["userName"].(string) // todo this may panic
	delete(resource, "schemas")

	emailDomain, err := emailaddr.Parse(userName)
	if err != nil {
		http.Error(w, "userName is not a valid email address", http.StatusBadRequest)
		return &badUsernameError{BadUsername: userName}
	}

	allowedDomains, err := s.Store.AuthGetSCIMDirectoryOrganizationDomains(ctx, scimDirectoryID)
	if err != nil {
		panic(err)
	}

	var domainOk bool
	for _, domain := range allowedDomains {
		if emailDomain == domain {
			domainOk = true
		}
	}

	if !domainOk {
		msg, err := json.Marshal(map[string]any{
			"status": http.StatusBadRequest,
			"detail": fmt.Sprintf("userName is not from the list of allowed domains: %s", strings.Join(allowedDomains, ", ")),
		})
		if err != nil {
			panic(err)
		}

		http.Error(w, string(msg), http.StatusBadRequest)
		return &emailOutsideOrgDomainsError{BadEmail: userName}
	}

	// at this point, all remaining properties are user attributes
	attributes, err := structpb.NewStruct(resource)
	if err != nil {
		panic(fmt.Errorf("convert attributes to structpb: %w", err))
	}

	scimUser, err := s.Store.AuthCreateSCIMUser(ctx, &store.AuthCreateSCIMUserRequest{
		SCIMUser: &ssoreadyv1.SCIMUser{
			ScimDirectoryId: scimDirectoryID,
			Email:           userName,
			Attributes:      attributes,
		},
	})
	if err != nil {
		panic(fmt.Errorf("store: %w", err))
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusCreated)

	response := scimUserToResource(scimUser.SCIMUser)
	response["schemas"] = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}

	w.Header().Set("Content-Type", "application/scim+json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
	return nil
}

func (s *Service) scimUpdateUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]
	scimUserID := mux.Vars(r)["scim_user_id"]

	defer r.Body.Close()
	var resource map[string]any
	if err := json.NewDecoder(r.Body).Decode(&resource); err != nil {
		return err
	}

	if resource["userName"] == nil {
		http.Error(w, "userName is required", http.StatusBadRequest)
		return &badUsernameError{BadUsername: ""}
	}
	if _, ok := resource["userName"]; !ok {
		http.Error(w, "userName is required", http.StatusBadRequest)
		return &badUsernameError{BadUsername: ""}
	}

	userName := resource["userName"].(string)

	// ensure active defaults to true if omitted in request
	if _, ok := resource["active"]; !ok {
		resource["active"] = true
	}

	delete(resource, "schemas")

	// at this point, all remaining properties are user attributes
	attributes, err := structpb.NewStruct(resource)
	if err != nil {
		panic(fmt.Errorf("convert attributes to structpb: %w", err))
	}

	emailDomain, err := emailaddr.Parse(userName)
	if err != nil {
		http.Error(w, "userName is not a valid email address", http.StatusBadRequest)
		return &badUsernameError{BadUsername: userName}
	}

	allowedDomains, err := s.Store.AuthGetSCIMDirectoryOrganizationDomains(ctx, scimDirectoryID)
	if err != nil {
		return err
	}

	var domainOk bool
	for _, domain := range allowedDomains {
		if emailDomain == domain {
			domainOk = true
		}
	}

	if !domainOk {
		msg, err := json.Marshal(map[string]any{
			"status": http.StatusBadRequest,
			"detail": fmt.Sprintf("userName is not from the list of allowed domains: %s", strings.Join(allowedDomains, ", ")),
		})
		if err != nil {
			panic(err)
		}

		http.Error(w, string(msg), http.StatusBadRequest)
		return &emailOutsideOrgDomainsError{BadEmail: userName}
	}

	scimUser, err := s.Store.AuthUpdateSCIMUser(ctx, &store.AuthUpdateSCIMUserRequest{
		SCIMUser: &ssoreadyv1.SCIMUser{
			Id:              scimUserID,
			ScimDirectoryId: scimDirectoryID,
			Email:           userName,
			Attributes:      attributes,
		},
	})
	if err != nil {
		if errors.Is(err, store.ErrSCIMUserNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return nil
		}
		return fmt.Errorf("store: %w", err)
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)

	response := scimUserToResource(scimUser.SCIMUser)
	response["schemas"] = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}

	w.Header().Set("Content-Type", "application/scim+json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	return nil
}

func (s *Service) scimPatchUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]
	scimUserID := mux.Vars(r)["scim_user_id"]

	var patch struct {
		Operations []scimpatch.Operation `json:"operations"`
	}

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		panic(err)
	}

	scimUser, err := s.Store.AuthGetSCIMUserIncludeDeleted(ctx, &store.AuthGetSCIMUserIncludeDeletedRequest{
		SCIMDirectoryID: scimDirectoryID,
		SCIMUserID:      scimUserID,
	})
	if err != nil {
		if errors.Is(err, store.ErrSCIMUserNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return nil
		}
		panic(fmt.Errorf("store: get scim user for patch: %w", err))
	}

	// Return 404 if user has been deleted
	if scimUser.Deleted {
		w.WriteHeader(http.StatusNotFound)
		return nil
	}

	// convert scimUser to its SCIM representation
	scimUserResource := scimUserToResource(scimUser)

	slog.InfoContext(ctx, "patched_user_fetch", "scim_user", scimUser, "scim_user_resource", scimUserResource)

	// apply patches
	if err := scimpatch.Patch(patch.Operations, &scimUserResource); err != nil {
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusBadRequest)
		errorResponse := map[string]interface{}{
			"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			"status":   "400",
			"scimType": "invalidPath",
			"detail":   fmt.Sprintf("Unsupported PATCH operation: %s", err.Error()),
		}
		if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
			panic(fmt.Errorf("encode error response: %w", err))
		}
		return nil
	}

	// convert back to our representation
	patchedSCIMUser := scimUserFromResource(scimDirectoryID, scimUserID, scimUserResource)

	// do not allow patches to remove the user email address
	if patchedSCIMUser.Email == "" {
		patchedSCIMUser.Email = scimUser.Email
	}

	slog.InfoContext(ctx, "patched_user_fetch", "patched_scim_user_resource", scimUserResource, "patched_scim_user", patchedSCIMUser)

	// validate email
	emailDomain, err := emailaddr.Parse(patchedSCIMUser.Email)
	if err != nil {
		http.Error(w, "userName is not a valid email address", http.StatusBadRequest)
		return &badUsernameError{BadUsername: patchedSCIMUser.Email}
	}

	allowedDomains, err := s.Store.AuthGetSCIMDirectoryOrganizationDomains(ctx, scimDirectoryID)
	if err != nil {
		return err
	}

	var domainOk bool
	for _, domain := range allowedDomains {
		if emailDomain == domain {
			domainOk = true
		}
	}

	if !domainOk {
		msg, err := json.Marshal(map[string]any{
			"status": http.StatusBadRequest,
			"detail": fmt.Sprintf("userName is not from the list of allowed domains: %s", strings.Join(allowedDomains, ", ")),
		})
		if err != nil {
			panic(err)
		}

		http.Error(w, string(msg), http.StatusBadRequest)
		return &emailOutsideOrgDomainsError{BadEmail: patchedSCIMUser.Email}
	}

	// write patched scim user back to database
	if _, err := s.Store.AuthUpdateSCIMUser(ctx, &store.AuthUpdateSCIMUserRequest{
		SCIMUser: patchedSCIMUser,
	}); err != nil {
		return fmt.Errorf("store: update patched user: %w", err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) scimDeleteUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]
	scimUserID := mux.Vars(r)["scim_user_id"]

	if err := s.Store.AuthDeleteSCIMUser(ctx, &store.AuthDeleteSCIMUserRequest{
		SCIMDirectoryID: scimDirectoryID,
		SCIMUserID:      scimUserID,
	}); err != nil {
		panic(err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) scimListGroups(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return nil
		}
		panic(err)
	}

	startIndex := 0
	if r.URL.Query().Get("startIndex") != "" {
		i, err := strconv.Atoi(r.URL.Query().Get("startIndex"))
		if err != nil {
			http.Error(w, fmt.Sprintf("parse startIndex: %s", err), http.StatusBadRequest)
			return nil
		}

		startIndex = i - 1 // scim is 1-indexed, store is 0-indexed
	}

	// parse count per RFC 7644 3.4.2.4
	// -1 means unspecified (use default), 0 means return only totalResults, negative values treated as 0
	count := -1 // default: unspecified, let store use default
	if r.URL.Query().Has("count") {
		c, err := strconv.Atoi(r.URL.Query().Get("count"))
		if err != nil {
			http.Error(w, fmt.Sprintf("parse count: %s", err), http.StatusBadRequest)
			return nil
		}
		// Per RFC 7644: negative values SHALL be interpreted as "0"
		if c < 0 {
			c = 0
		}
		count = c
	}

	// Use unified filter parsing - supports RFC 7644 compliant filters
	// Empty filter string is handled gracefully (returns all groups)
	filter := r.URL.Query().Get("filter")
	scimGroups, err := s.Store.AuthListSCIMGroupsFiltered(ctx, &store.AuthListSCIMGroupsFilteredRequest{
		SCIMDirectoryID: scimDirectoryID,
		Filter:          filter,
		StartIndex:      startIndex,
		Count:           count,
	})
	if err != nil {
		if errors.Is(err, store.ErrInvalidSCIMFilter) {
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]any{
				"schemas":  []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
				"scimType": "invalidFilter",
				"detail":   err.Error(),
				"status":   400,
			}); err != nil {
				panic(err)
			}
			return nil
		}
		panic(fmt.Errorf("store: %w", err))
	}

	resources := []any{} // intentionally initialized to avoid returning `null` instead of `[]`
	for _, scimGroup := range scimGroups.SCIMGroups {
		resource := scimGroup.Attributes.AsMap()
		resource["id"] = scimGroup.Id
		resource["displayName"] = scimGroup.DisplayName

		resources = append(resources, resource)
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(scimListResponse{
		TotalResults: scimGroups.TotalResults,
		ItemsPerPage: len(resources),
		StartIndex:   startIndex + 1, // convert back to 1-indexed for response
		Schemas:      []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		Resources:    resources,
	}); err != nil {
		panic(err)
	}
	return nil
}

func (s *Service) scimGetGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]
	scimGroupID := mux.Vars(r)["scim_group_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return nil
		}
		panic(err)
	}

	scimGroup, err := s.Store.AuthGetSCIMGroup(ctx, &store.AuthGetSCIMGroupRequest{
		SCIMDirectoryID: scimDirectoryID,
		SCIMGroupID:     scimGroupID,
	})
	if err != nil {
		if errors.Is(err, store.ErrSCIMGroupNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return nil
		}
		panic(err)
	}

	resource := scimGroup.Attributes.AsMap()
	resource["id"] = scimGroup.Id
	resource["displayName"] = scimGroup.DisplayName
	resource["schemas"] = []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resource); err != nil {
		panic(err)
	}
	return nil
}

func (s *Service) scimCreateGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return nil
		}
		panic(err)
	}

	defer r.Body.Close()
	var resource map[string]any
	if err := json.NewDecoder(r.Body).Decode(&resource); err != nil {
		panic(err)
	}

	var memberSCIMUserIDs []string
	if members, ok := resource["members"]; ok {
		members := members.([]any)
		for _, member := range members {
			member := member.(map[string]any)
			userID := member["value"].(string)
			memberSCIMUserIDs = append(memberSCIMUserIDs, userID)
		}
	}

	displayName := resource["displayName"].(string)
	delete(resource, "schemas")

	// at this point, all remaining properties are user attributes
	attributes, err := structpb.NewStruct(resource)
	if err != nil {
		panic(fmt.Errorf("convert attributes to structpb: %w", err))
	}

	scimGroup, err := s.Store.AuthCreateSCIMGroup(ctx, &store.AuthCreateSCIMGroupRequest{
		SCIMGroup: &ssoreadyv1.SCIMGroup{
			ScimDirectoryId: scimDirectoryID,
			DisplayName:     displayName,
			Attributes:      attributes,
		},
		MemberSCIMUserIDs: memberSCIMUserIDs,
	})
	if err != nil {
		panic(fmt.Errorf("store: %w", err))
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusCreated)

	response := scimGroup.SCIMGroup.Attributes.AsMap()
	response["schemas"] = []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}
	response["id"] = scimGroup.SCIMGroup.Id
	var responseMembers []map[string]any
	for _, userID := range scimGroup.MemberSCIMUserIDs {
		responseMembers = append(responseMembers, map[string]any{
			"value": userID,
		})
	}
	response["members"] = responseMembers

	w.Header().Set("Content-Type", "application/scim+json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
	return nil
}

func (s *Service) scimDeleteGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]
	scimGroupID := mux.Vars(r)["scim_group_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return nil
		}
		panic(err)
	}

	if err := s.Store.AuthDeleteSCIMGroup(ctx, &store.AuthDeleteSCIMGroupRequest{
		SCIMDirectoryID: scimDirectoryID,
		SCIMGroupID:     scimGroupID,
	}); err != nil {
		panic(err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Service) scimUpdateGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]
	scimGroupID := mux.Vars(r)["scim_group_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return nil
		}
		panic(err)
	}

	defer r.Body.Close()
	var resource map[string]any
	if err := json.NewDecoder(r.Body).Decode(&resource); err != nil {
		panic(err)
	}

	var memberSCIMUserIDs []string
	if resource["members"] != nil {
		members := resource["members"].([]any)
		for _, member := range members {
			member := member.(map[string]any)
			userID := member["value"].(string)
			memberSCIMUserIDs = append(memberSCIMUserIDs, userID)
		}
	}

	displayName := resource["displayName"].(string)
	delete(resource, "schemas")

	// at this point, all remaining properties are user attributes
	attributes, err := structpb.NewStruct(resource)
	if err != nil {
		panic(fmt.Errorf("convert attributes to structpb: %w", err))
	}

	scimGroup, err := s.Store.AuthUpdateSCIMGroup(ctx, &store.AuthUpdateSCIMGroupRequest{
		SCIMGroup: &ssoreadyv1.SCIMGroup{
			Id:              scimGroupID,
			ScimDirectoryId: scimDirectoryID,
			DisplayName:     displayName,
			Attributes:      attributes,
		},
		MemberSCIMUserIDs: memberSCIMUserIDs,
	})
	if err != nil {
		panic(fmt.Errorf("store: %w", err))
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)

	response := scimGroup.SCIMGroup.Attributes.AsMap()
	response["schemas"] = []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}
	response["id"] = scimGroup.SCIMGroup.Id
	var responseMembers []map[string]any
	for _, userID := range scimGroup.MemberSCIMUserIDs {
		responseMembers = append(responseMembers, map[string]any{
			"value": userID,
		})
	}
	response["members"] = responseMembers

	if err := json.NewEncoder(w).Encode(response); err != nil {
		panic(err)
	}
	return nil
}

func (s *Service) scimPatchGroup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]
	scimGroupID := mux.Vars(r)["scim_group_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return nil
		}
		panic(err)
	}

	var patch struct {
		Operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value any    `json:"value"`
		} `json:"operations"`
	}

	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		panic(err)
	}

	// jumpcloud changes group display names via a top-level replace
	if len(patch.Operations) == 1 && patch.Operations[0].Op == "replace" && patch.Operations[0].Path == "" {
		value := patch.Operations[0].Value.(map[string]any)
		displayName := value["displayName"].(string)

		if err := s.Store.AuthUpdateSCIMGroupDisplayName(ctx, &ssoreadyv1.SCIMGroup{
			Id:              scimGroupID,
			ScimDirectoryId: scimDirectoryID,
			DisplayName:     displayName,
		}); err != nil {
			panic(fmt.Errorf("store: %w", err))
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	// jumpcloud adds members to groups via an `add` on members; entra uses an `Add`
	if len(patch.Operations) == 1 && (patch.Operations[0].Op == "add" || patch.Operations[0].Op == "Add") && patch.Operations[0].Path == "members" {
		value := patch.Operations[0].Value.([]any)
		scimUserID := value[0].(map[string]any)["value"].(string)

		if err := s.Store.AuthAddSCIMGroupMember(ctx, &store.AuthAddSCIMGroupMemberRequest{
			SCIMGroup: &ssoreadyv1.SCIMGroup{
				Id:              scimGroupID,
				ScimDirectoryId: scimDirectoryID,
			},
			SCIMUserID: scimUserID,
		}); err != nil {
			if errors.Is(err, store.ErrBadSCIMUserID) {
				http.Error(w, "bad scim user id", http.StatusBadRequest)
				return nil
			}

			panic(fmt.Errorf("store: %w", err))
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	// entra removes members via a `remove` on members with a value
	if len(patch.Operations) == 1 && (patch.Operations[0].Op == "remove" || patch.Operations[0].Op == "Remove") && patch.Operations[0].Path == "members" {
		value := patch.Operations[0].Value.([]any)
		scimUserID := value[0].(map[string]any)["value"].(string)

		if err := s.Store.AuthRemoveSCIMGroupMember(ctx, &store.AuthRemoveSCIMGroupMemberRequest{
			SCIMGroup: &ssoreadyv1.SCIMGroup{
				Id:              scimGroupID,
				ScimDirectoryId: scimDirectoryID,
			},
			SCIMUserID: scimUserID,
		}); err != nil {
			panic(fmt.Errorf("store: %w", err))
		}

		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	panic("unsupported group PATCH operation type")
}

// scimUserToResource converts our representation of a scim user to its SCIM HTTP representation
func scimUserToResource(scimUser *ssoreadyv1.SCIMUser) map[string]any {
	r := scimUser.Attributes.AsMap()
	r["id"] = scimUser.Id
	r["userName"] = scimUser.Email

	// normalize Entra-style "active" property
	switch r["active"] {
	case "True":
		r["active"] = true
	case "False":
		r["active"] = false
	}

	// convert simple manager id reference to complex manager reference for Entra compatibility
	if r["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] != nil {
		enterpriseUser := r["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].(map[string]any)
		if enterpriseUser["manager"] != nil {
			if managerID, ok := enterpriseUser["manager"].(string); ok {
				enterpriseUser["manager"] = map[string]any{
					"value": managerID,
				}
			}
		}
	}

	return r
}

func scimUserFromResource(scimDirectoryID, scimUserID string, r map[string]any) *ssoreadyv1.SCIMUser {
	// if included, id and schemas are not attributes
	delete(r, "id")
	delete(r, "schemas")

	// normalize Entra-style "active" property
	switch r["active"] {
	case "True":
		r["active"] = true
	case "False":
		r["active"] = false
	}

	attrs, err := structpb.NewStruct(r)
	if err != nil {
		panic(fmt.Errorf("convert attributes to structpb: %w", err))
	}

	email, _ := r["userName"].(string)

	// Note: active state is stored in attributes, not mapped to Deleted.
	// Deleted is only set via DELETE operations (SCIM compliant).
	return &ssoreadyv1.SCIMUser{
		Id:              scimUserID,
		ScimDirectoryId: scimDirectoryID,
		Email:           email,
		Deleted:         false,
		Attributes:      attrs,
	}
}

type badUsernameError struct {
	BadUsername string
}

func (e *badUsernameError) Error() string {
	return fmt.Sprintf("bad username: %v", e.BadUsername)
}

type emailOutsideOrgDomainsError struct {
	BadEmail string
}

func (e *emailOutsideOrgDomainsError) Error() string {
	return fmt.Sprintf("email outside organization domains: %v", e.BadEmail)
}

// scimMiddleware verifies scim bearer tokens and creates scim request logs in the database.
//
// To detect the error cases of bad usernames and emails outside org domains, scimMiddleware takes an f that returns an
// error. If that error is a badUsernameError or emailOutsideOrgDomainsError, the logged scim request is appropriately
// marked as such.
func (s *Service) scimMiddleware(f func(w http.ResponseWriter, r *http.Request) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		scimDirectoryID := mux.Vars(r)["scim_directory_id"]

		// check scim dir exists, and 404 immediately if not; we can't create a scim request for this case anyway
		if err := s.Store.AuthCheckSCIMDirectoryExists(ctx, scimDirectoryID); err != nil {
			if errors.Is(err, store.ErrNoSuchSCIMDirectory) {
				http.Error(w, "scim directory not found", http.StatusNotFound)
				return
			}

			panic(err)
		}

		defer r.Body.Close()
		reqBody, err := io.ReadAll(r.Body)
		if err != nil {
			panic(fmt.Errorf("read body: %w", err))
		}

		var scimRequestMethod ssoreadyv1.SCIMRequestHTTPMethod
		switch r.Method {
		case http.MethodGet:
			scimRequestMethod = ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_GET
		case http.MethodPost:
			scimRequestMethod = ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_POST
		case http.MethodPut:
			scimRequestMethod = ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_PUT
		case http.MethodPatch:
			scimRequestMethod = ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_PATCH
		case http.MethodDelete:
			scimRequestMethod = ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_DELETE
		}

		var scimRequestBody *structpb.Struct
		if len(reqBody) > 0 {
			if err := json.Unmarshal(reqBody, &scimRequestBody); err != nil {
				panic(err)
			}
		}

		scimRequest := &ssoreadyv1.SCIMRequest{
			ScimDirectoryId:   scimDirectoryID,
			Timestamp:         timestamppb.New(time.Now()),
			HttpRequestUrl:    r.URL.String(),
			HttpRequestMethod: scimRequestMethod,
			HttpRequestBody:   scimRequestBody,
		}

		// rewrite the response to be a recorded one, and the request to have the original body
		recorder := httptest.NewRecorder()

		// Make a copy of reqBody to work with later
		bodyCopy := make([]byte, len(reqBody))
		copy(bodyCopy, reqBody)

		// Set the copied reqBody back to r.Body
		r.Body = io.NopCloser(bytes.NewBuffer(bodyCopy))

		// check bearer token before calling f
		bearerToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if err := s.Store.AuthSCIMVerifyBearerToken(ctx, scimDirectoryID, bearerToken); err != nil {
			if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
				// log a failed scim request
				scimRequest.HttpResponseStatus = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_401
				scimRequest.Error = &ssoreadyv1.SCIMRequest_BadBearerToken{BadBearerToken: &emptypb.Empty{}}
				if _, err := s.Store.AuthCreateSCIMRequest(ctx, scimRequest); err != nil {
					panic(err)
				}

				http.Error(w, "invalid bearer token", http.StatusUnauthorized)
				return
			}

			panic(err)
		}

		// call the underlying f
		if err := f(recorder, r); err != nil {
			var badUsernameError *badUsernameError
			var badEmailError *emailOutsideOrgDomainsError

			if errors.As(err, &badUsernameError) {
				scimRequest.Error = &ssoreadyv1.SCIMRequest_BadUsername{BadUsername: badUsernameError.BadUsername}
			} else if errors.As(err, &badEmailError) {
				scimRequest.Error = &ssoreadyv1.SCIMRequest_EmailOutsideOrganizationDomains{EmailOutsideOrganizationDomains: badEmailError.BadEmail}
			} else {
				panic(err)
			}
		}

		switch recorder.Code {
		case http.StatusOK:
			scimRequest.HttpResponseStatus = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_200
		case http.StatusCreated:
			scimRequest.HttpResponseStatus = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_201
		case http.StatusNoContent:
			scimRequest.HttpResponseStatus = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_204
		case http.StatusBadRequest:
			scimRequest.HttpResponseStatus = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_400
		case http.StatusNotFound:
			scimRequest.HttpResponseStatus = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_404
		}

		if err := json.Unmarshal(recorder.Body.Bytes(), &scimRequest.HttpResponseBody); err != nil {
			// can't use errors.Is, because json's errors aren't comparable
			if _, ok := err.(*json.SyntaxError); ok {
				// ignore this error; we only care to record JSON responses, and so just record no response body at all
			} else {
				panic(err)
			}
		}

		if _, err := s.Store.AuthCreateSCIMRequest(ctx, scimRequest); err != nil {
			panic(err)
		}

		// write out recorded response to w
		for k, v := range recorder.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(recorder.Code)
		if _, err := recorder.Body.WriteTo(w); err != nil {
			panic(fmt.Errorf("write reqBody: %w", err))
		}
	})
}

func (s *Service) scimVerifyBearerToken(ctx context.Context, scimDirectoryID, authorization string) error {
	bearerToken := strings.TrimPrefix(authorization, "Bearer ")
	return s.Store.AuthSCIMVerifyBearerToken(ctx, scimDirectoryID, bearerToken)
}

// SCIM Schema definitions per RFC 7643

var scimUserSchema = map[string]any{
	"id":          "urn:ietf:params:scim:schemas:core:2.0:User",
	"name":        "User",
	"description": "User Account",
	"attributes": []map[string]any{
		{
			"name":        "userName",
			"type":        "string",
			"multiValued": false,
			"description": "Unique identifier for the User, typically used by the user to directly authenticate to the service provider.",
			"required":    true,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "server",
		},
		{
			"name":        "name",
			"type":        "complex",
			"multiValued": false,
			"description": "The components of the user's real name.",
			"required":    false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
			"subAttributes": []map[string]any{
				{"name": "formatted", "type": "string", "multiValued": false, "description": "The full name, including all middle names, titles, and suffixes as appropriate, formatted for display.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "familyName", "type": "string", "multiValued": false, "description": "The family name of the User, or last name in most Western languages.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "givenName", "type": "string", "multiValued": false, "description": "The given name of the User, or first name in most Western languages.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "middleName", "type": "string", "multiValued": false, "description": "The middle name(s) of the User.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "honorificPrefix", "type": "string", "multiValued": false, "description": "The honorific prefix(es) of the User, or title in most Western languages.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "honorificSuffix", "type": "string", "multiValued": false, "description": "The honorific suffix(es) of the User, or suffix in most Western languages.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
			},
		},
		{
			"name":        "displayName",
			"type":        "string",
			"multiValued": false,
			"description": "The name of the User, suitable for display to end-users.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "nickName",
			"type":        "string",
			"multiValued": false,
			"description": "The casual way to address the user in real life.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "profileUrl",
			"type":        "reference",
			"multiValued": false,
			"description": "A fully qualified URL pointing to a page representing the User's online profile.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
			"referenceTypes": []string{"external"},
		},
		{
			"name":        "title",
			"type":        "string",
			"multiValued": false,
			"description": "The user's title, such as Vice President.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "userType",
			"type":        "string",
			"multiValued": false,
			"description": "Used to identify the relationship between the organization and the user.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "preferredLanguage",
			"type":        "string",
			"multiValued": false,
			"description": "Indicates the User's preferred written or spoken language.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "locale",
			"type":        "string",
			"multiValued": false,
			"description": "Used to indicate the User's default location for purposes of localizing items such as currency, date time format, or numerical representations.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "timezone",
			"type":        "string",
			"multiValued": false,
			"description": "The User's time zone in the 'Olson' time zone database format.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "active",
			"type":        "boolean",
			"multiValued": false,
			"description": "A Boolean value indicating the User's administrative status.",
			"required":    false,
			"mutability":  "readWrite",
			"returned":    "default",
		},
		{
			"name":        "password",
			"type":        "string",
			"multiValued": false,
			"description": "The User's cleartext password.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "writeOnly",
			"returned":    "never",
			"uniqueness":  "none",
		},
		{
			"name":        "emails",
			"type":        "complex",
			"multiValued": true,
			"description": "Email addresses for the user.",
			"required":    false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
			"subAttributes": []map[string]any{
				{"name": "value", "type": "string", "multiValued": false, "description": "Email address value.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "display", "type": "string", "multiValued": false, "description": "A human-readable name, primarily used for display purposes.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "type", "type": "string", "multiValued": false, "description": "A label indicating the attribute's function.", "required": false, "caseExact": false, "canonicalValues": []string{"work", "home", "other"}, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "primary", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.", "required": false, "mutability": "readWrite", "returned": "default"},
			},
		},
		{
			"name":        "phoneNumbers",
			"type":        "complex",
			"multiValued": true,
			"description": "Phone numbers for the User.",
			"required":    false,
			"mutability":  "readWrite",
			"returned":    "default",
			"subAttributes": []map[string]any{
				{"name": "value", "type": "string", "multiValued": false, "description": "Phone number value.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "display", "type": "string", "multiValued": false, "description": "A human-readable name, primarily used for display purposes.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "type", "type": "string", "multiValued": false, "description": "A label indicating the attribute's function.", "required": false, "caseExact": false, "canonicalValues": []string{"work", "home", "mobile", "fax", "pager", "other"}, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "primary", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.", "required": false, "mutability": "readWrite", "returned": "default"},
			},
		},
		{
			"name":        "addresses",
			"type":        "complex",
			"multiValued": true,
			"description": "A physical mailing address for this User.",
			"required":    false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
			"subAttributes": []map[string]any{
				{"name": "formatted", "type": "string", "multiValued": false, "description": "The full mailing address, formatted for display or use with a mailing label.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "streetAddress", "type": "string", "multiValued": false, "description": "The full street address component.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "locality", "type": "string", "multiValued": false, "description": "The city or locality component.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "region", "type": "string", "multiValued": false, "description": "The state or region component.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "postalCode", "type": "string", "multiValued": false, "description": "The zip code or postal code component.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "country", "type": "string", "multiValued": false, "description": "The country name component.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "type", "type": "string", "multiValued": false, "description": "A label indicating the attribute's function.", "required": false, "caseExact": false, "canonicalValues": []string{"work", "home", "other"}, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "primary", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.", "required": false, "mutability": "readWrite", "returned": "default"},
			},
		},
		{
			"name":        "groups",
			"type":        "complex",
			"multiValued": true,
			"description": "A list of groups to which the user belongs.",
			"required":    false,
			"mutability":  "readOnly",
			"returned":    "default",
			"subAttributes": []map[string]any{
				{"name": "value", "type": "string", "multiValued": false, "description": "The identifier of the User's group.", "required": false, "caseExact": false, "mutability": "readOnly", "returned": "default", "uniqueness": "none"},
				{"name": "$ref", "type": "reference", "multiValued": false, "description": "The URI of the corresponding 'Group' resource to which the user belongs.", "required": false, "caseExact": false, "mutability": "readOnly", "returned": "default", "uniqueness": "none", "referenceTypes": []string{"User", "Group"}},
				{"name": "display", "type": "string", "multiValued": false, "description": "A human-readable name, primarily used for display purposes.", "required": false, "caseExact": false, "mutability": "readOnly", "returned": "default", "uniqueness": "none"},
				{"name": "type", "type": "string", "multiValued": false, "description": "A label indicating the attribute's function.", "required": false, "caseExact": false, "canonicalValues": []string{"direct", "indirect"}, "mutability": "readOnly", "returned": "default", "uniqueness": "none"},
			},
		},
		{
			"name":        "entitlements",
			"type":        "complex",
			"multiValued": true,
			"description": "A list of entitlements for the User that represent a thing the User has.",
			"required":    false,
			"mutability":  "readWrite",
			"returned":    "default",
			"subAttributes": []map[string]any{
				{"name": "value", "type": "string", "multiValued": false, "description": "The value of an entitlement.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "display", "type": "string", "multiValued": false, "description": "A human-readable name, primarily used for display purposes.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "type", "type": "string", "multiValued": false, "description": "A label indicating the attribute's function.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "primary", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.", "required": false, "mutability": "readWrite", "returned": "default"},
			},
		},
		{
			"name":        "roles",
			"type":        "complex",
			"multiValued": true,
			"description": "A list of roles for the User that collectively represent who the User is.",
			"required":    false,
			"mutability":  "readWrite",
			"returned":    "default",
			"subAttributes": []map[string]any{
				{"name": "value", "type": "string", "multiValued": false, "description": "The value of a role.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "display", "type": "string", "multiValued": false, "description": "A human-readable name, primarily used for display purposes.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "type", "type": "string", "multiValued": false, "description": "A label indicating the attribute's function.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "primary", "type": "boolean", "multiValued": false, "description": "A Boolean value indicating the 'primary' or preferred attribute value for this attribute.", "required": false, "mutability": "readWrite", "returned": "default"},
			},
		},
	},
	"meta": map[string]any{
		"resourceType": "Schema",
		"location":     "/v1/scim/{scim_directory_id}/Schemas/urn:ietf:params:scim:schemas:core:2.0:User",
	},
}

var scimGroupSchema = map[string]any{
	"id":          "urn:ietf:params:scim:schemas:core:2.0:Group",
	"name":        "Group",
	"description": "Group",
	"attributes": []map[string]any{
		{
			"name":        "displayName",
			"type":        "string",
			"multiValued": false,
			"description": "A human-readable name for the Group.",
			"required":    true,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "members",
			"type":        "complex",
			"multiValued": true,
			"description": "A list of members of the Group.",
			"required":    false,
			"mutability":  "readWrite",
			"returned":    "default",
			"subAttributes": []map[string]any{
				{"name": "value", "type": "string", "multiValued": false, "description": "Identifier of the member of this Group.", "required": false, "caseExact": false, "mutability": "immutable", "returned": "default", "uniqueness": "none"},
				{"name": "$ref", "type": "reference", "multiValued": false, "description": "The URI corresponding to a SCIM resource that is a member of this Group.", "required": false, "caseExact": false, "mutability": "immutable", "returned": "default", "uniqueness": "none", "referenceTypes": []string{"User", "Group"}},
				{"name": "type", "type": "string", "multiValued": false, "description": "A label indicating the type of resource.", "required": false, "caseExact": false, "canonicalValues": []string{"User", "Group"}, "mutability": "immutable", "returned": "default", "uniqueness": "none"},
				{"name": "display", "type": "string", "multiValued": false, "description": "A human-readable name for the member.", "required": false, "caseExact": false, "mutability": "readOnly", "returned": "default", "uniqueness": "none"},
			},
		},
	},
	"meta": map[string]any{
		"resourceType": "Schema",
		"location":     "/v1/scim/{scim_directory_id}/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group",
	},
}

var scimEnterpriseUserSchema = map[string]any{
	"id":          "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
	"name":        "EnterpriseUser",
	"description": "Enterprise User",
	"attributes": []map[string]any{
		{
			"name":        "employeeNumber",
			"type":        "string",
			"multiValued": false,
			"description": "Numeric or alphanumeric identifier assigned to a person, typically based on order of hire or association with an organization.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "costCenter",
			"type":        "string",
			"multiValued": false,
			"description": "Identifies the name of a cost center.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "organization",
			"type":        "string",
			"multiValued": false,
			"description": "Identifies the name of an organization.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "division",
			"type":        "string",
			"multiValued": false,
			"description": "Identifies the name of a division.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "department",
			"type":        "string",
			"multiValued": false,
			"description": "Identifies the name of a department.",
			"required":    false,
			"caseExact":   false,
			"mutability":  "readWrite",
			"returned":    "default",
			"uniqueness":  "none",
		},
		{
			"name":        "manager",
			"type":        "complex",
			"multiValued": false,
			"description": "The User's manager.",
			"required":    false,
			"mutability":  "readWrite",
			"returned":    "default",
			"subAttributes": []map[string]any{
				{"name": "value", "type": "string", "multiValued": false, "description": "The id of the SCIM resource representing the User's manager.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
				{"name": "$ref", "type": "reference", "multiValued": false, "description": "The URI of the SCIM resource representing the User's manager.", "required": false, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "none", "referenceTypes": []string{"User"}},
				{"name": "displayName", "type": "string", "multiValued": false, "description": "The displayName of the User's manager.", "required": false, "caseExact": false, "mutability": "readOnly", "returned": "default", "uniqueness": "none"},
			},
		},
	},
	"meta": map[string]any{
		"resourceType": "Schema",
		"location":     "/v1/scim/{scim_directory_id}/Schemas/urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
	},
}

func (s *Service) scimGetSchemas(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return err
		}
		panic(err)
	}

	// Build schemas with correct location URLs
	baseURL := fmt.Sprintf("/v1/scim/%s", scimDirectoryID)

	userSchema := copySchemaWithLocation(scimUserSchema, baseURL)
	groupSchema := copySchemaWithLocation(scimGroupSchema, baseURL)
	enterpriseUserSchema := copySchemaWithLocation(scimEnterpriseUserSchema, baseURL)

	schemas := []any{userSchema, groupSchema, enterpriseUserSchema}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(schemas),
		"Resources":    schemas,
	}); err != nil {
		panic(err)
	}
	return nil
}

func (s *Service) scimGetSchema(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]
	schemaID := mux.Vars(r)["schema_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return err
		}
		panic(err)
	}

	baseURL := fmt.Sprintf("/v1/scim/%s", scimDirectoryID)

	var schema map[string]any
	switch schemaID {
	case "urn:ietf:params:scim:schemas:core:2.0:User":
		schema = copySchemaWithLocation(scimUserSchema, baseURL)
	case "urn:ietf:params:scim:schemas:core:2.0:Group":
		schema = copySchemaWithLocation(scimGroupSchema, baseURL)
	case "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":
		schema = copySchemaWithLocation(scimEnterpriseUserSchema, baseURL)
	default:
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			"detail":  fmt.Sprintf("Schema %q not found", schemaID),
			"status":  404,
		}); err != nil {
			panic(err)
		}
		return nil
	}

	schema["schemas"] = []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(schema); err != nil {
		panic(err)
	}
	return nil
}

func (s *Service) scimGetResourceTypes(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return err
		}
		panic(err)
	}

	baseURL := fmt.Sprintf("/v1/scim/%s", scimDirectoryID)

	resourceTypes := []map[string]any{
		{
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
				"location":     fmt.Sprintf("%s/ResourceTypes/User", baseURL),
				"resourceType": "ResourceType",
			},
		},
		{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/Groups",
			"description": "Group",
			"schema":      "urn:ietf:params:scim:schemas:core:2.0:Group",
			"meta": map[string]any{
				"location":     fmt.Sprintf("%s/ResourceTypes/Group", baseURL),
				"resourceType": "ResourceType",
			},
		},
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(resourceTypes),
		"Resources":    resourceTypes,
	}); err != nil {
		panic(err)
	}
	return nil
}

func (s *Service) scimGetResourceType(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]
	resourceTypeID := mux.Vars(r)["resource_type_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return err
		}
		panic(err)
	}

	baseURL := fmt.Sprintf("/v1/scim/%s", scimDirectoryID)

	var resourceType map[string]any
	switch resourceTypeID {
	case "User":
		resourceType = map[string]any{
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
				"location":     fmt.Sprintf("%s/ResourceTypes/User", baseURL),
				"resourceType": "ResourceType",
			},
		}
	case "Group":
		resourceType = map[string]any{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/Groups",
			"description": "Group",
			"schema":      "urn:ietf:params:scim:schemas:core:2.0:Group",
			"meta": map[string]any{
				"location":     fmt.Sprintf("%s/ResourceTypes/Group", baseURL),
				"resourceType": "ResourceType",
			},
		}
	default:
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusNotFound)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
			"detail":  fmt.Sprintf("ResourceType %q not found", resourceTypeID),
			"status":  404,
		}); err != nil {
			panic(err)
		}
		return nil
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resourceType); err != nil {
		panic(err)
	}
	return nil
}

// copySchemaWithLocation creates a copy of a schema with the correct location URL
func copySchemaWithLocation(schema map[string]any, baseURL string) map[string]any {
	// Create a shallow copy
	result := make(map[string]any)
	for k, v := range schema {
		result[k] = v
	}

	// Update meta with correct location
	schemaID := schema["id"].(string)
	result["meta"] = map[string]any{
		"resourceType": "Schema",
		"location":     fmt.Sprintf("%s/Schemas/%s", baseURL, schemaID),
	}

	return result
}

func (s *Service) scimGetServiceProviderConfig(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scimDirectoryID := mux.Vars(r)["scim_directory_id"]

	if err := s.scimVerifyBearerToken(ctx, scimDirectoryID, r.Header.Get("Authorization")); err != nil {
		if errors.Is(err, store.ErrAuthSCIMBadBearerToken) {
			http.Error(w, "invalid bearer token", http.StatusUnauthorized)
			return err
		}
		panic(err)
	}

	baseURL := fmt.Sprintf("/v1/scim/%s", scimDirectoryID)

	// ServiceProviderConfig per RFC 7643 Section 5
	config := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
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
			"location":     fmt.Sprintf("%s/ServiceProviderConfig", baseURL),
			"resourceType": "ServiceProviderConfig",
		},
	}

	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(config); err != nil {
		panic(err)
	}
	return nil
}

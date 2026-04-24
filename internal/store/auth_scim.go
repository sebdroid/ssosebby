package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	ssoreadyv1 "github.com/sebdroid/ssosebby/internal/gen/ssoready/v1"
	"github.com/sebdroid/ssosebby/internal/scimfilter"
	"github.com/sebdroid/ssosebby/internal/store/idformat"
	"github.com/sebdroid/ssosebby/internal/store/queries"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrNoSuchSCIMDirectory = errors.New("no such scim directory")

// DefaultSCIMPageSize is the default number of results returned per page when count is not specified.
// Per RFC 7644 section 3.4.2.4, the service provider establishes its own maximum when count is not specified.
const DefaultSCIMPageSize = 10

// MaxSCIMPageSize is the maximum allowed page size for SCIM list operations.
const MaxSCIMPageSize = 200

func (s *Store) AuthCheckSCIMDirectoryExists(ctx context.Context, scimDirectoryID string) error {
	scimDirID, err := idformat.SCIMDirectory.Parse(scimDirectoryID)
	if err != nil {
		return fmt.Errorf("parse scim directory id: %w", err)
	}

	if _, err := s.q.AuthGetSCIMDirectory(ctx, scimDirID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSuchSCIMDirectory
		}
		return fmt.Errorf("get scim directory: %w", err)
	}
	return nil
}

func (s *Store) AuthGetSCIMDirectoryOrganizationDomains(ctx context.Context, scimDirectoryID string) ([]string, error) {
	scimDirID, err := idformat.SCIMDirectory.Parse(scimDirectoryID)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	domains, err := s.q.AuthGetSCIMDirectoryOrganizationDomains(ctx, scimDirID)
	if err != nil {
		return nil, fmt.Errorf("get scim directory organization domains: %w", err)
	}

	return domains, nil
}

var ErrAuthSCIMBadBearerToken = errors.New("store: bad scim directory bearer token")

func (s *Store) AuthSCIMVerifyBearerToken(ctx context.Context, scimDirectoryID, bearerToken string) error {
	scimDirID, err := idformat.SCIMDirectory.Parse(scimDirectoryID)
	if err != nil {
		return fmt.Errorf("parse scim directory id: %w", err)
	}

	bearerTokenID, err := idformat.SCIMBearerToken.Parse(bearerToken)
	if err != nil {
		return ErrAuthSCIMBadBearerToken
	}

	bearerTokenSHA := sha256.Sum256(bearerTokenID[:])

	if _, err := s.q.AuthGetSCIMDirectoryByIDAndBearerToken(ctx, queries.AuthGetSCIMDirectoryByIDAndBearerTokenParams{
		ID:                scimDirID,
		BearerTokenSha256: bearerTokenSHA[:],
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAuthSCIMBadBearerToken
		}

		return fmt.Errorf("get scim directory: %w", err)
	}

	return nil
}

type AuthListSCIMUsersFilteredRequest struct {
	SCIMDirectoryID string
	Filter          string
	StartIndex      int
	Count           int // Per RFC 7644 3.4.2.4: desired max results per page. 0 = return only totalResults, -1 = use default
}

type AuthListSCIMUsersFilteredResponse struct {
	TotalResults int
	SCIMUsers    []*ssoreadyv1.SCIMUser
}

var ErrInvalidSCIMFilter = errors.New("store: invalid scim filter")

func (s *Store) AuthListSCIMUsersFiltered(ctx context.Context, req *AuthListSCIMUsersFilteredRequest) (*AuthListSCIMUsersFilteredResponse, error) {
	var scimDirID uuid.UUID
	var err error
	scimDirID, err = idformat.SCIMDirectory.Parse(req.SCIMDirectoryID)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	// Parse the SCIM filter to squirrel conditions
	parsedFilter, err := scimfilter.ParseToSquirrel(req.Filter, scimfilter.ResourceTypeUser)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSCIMFilter, err)
	}

	// Build base query with squirrel (uses $1, $2, etc. for PostgreSQL)
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	// Count query
	countBuilder := psql.Select("count(*)").From("scim_users").
		Where(sq.Eq{"scim_directory_id": scimDirID}).
		Where(sq.Eq{"deleted": false})
	if parsedFilter.Where != nil {
		countBuilder = countBuilder.Where(parsedFilter.Where)
	}

	countSQL, countArgs, err := countBuilder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build count query: %w", err)
	}

	var count int64
	if err := s.db.QueryRow(ctx, countSQL, countArgs...).Scan(&count); err != nil {
		return nil, fmt.Errorf("count filtered scim users: %w", err)
	}

	// Per RFC 7644 3.4.2.4: count=0 means return only totalResults
	if req.Count == 0 {
		return &AuthListSCIMUsersFilteredResponse{
			TotalResults: int(count),
			SCIMUsers:    nil,
		}, nil
	}

	// Determine effective limit: negative means use default, otherwise cap at max
	limit := DefaultSCIMPageSize
	if req.Count > 0 {
		limit = min(req.Count, MaxSCIMPageSize)
	}

	// List query
	listBuilder := psql.Select("id", "scim_directory_id", "email", "deleted", "attributes").
		From("scim_users").
		Where(sq.Eq{"scim_directory_id": scimDirID}).
		Where(sq.Eq{"deleted": false}).
		OrderBy("id").
		Offset(uint64(req.StartIndex)).
		Limit(uint64(limit))
	if parsedFilter.Where != nil {
		listBuilder = listBuilder.Where(parsedFilter.Where)
	}

	listSQL, listArgs, err := listBuilder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list query: %w", err)
	}

	rows, err := s.db.Query(ctx, listSQL, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("list filtered scim users: %w", err)
	}
	defer rows.Close()

	var scimUsers []*ssoreadyv1.SCIMUser
	for rows.Next() {
		var qUser queries.ScimUser
		if err := rows.Scan(&qUser.ID, &qUser.ScimDirectoryID, &qUser.Email, &qUser.Deleted, &qUser.Attributes); err != nil {
			return nil, fmt.Errorf("scan scim user: %w", err)
		}
		scimUsers = append(scimUsers, parseSCIMUser(qUser))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scim users: %w", err)
	}

	return &AuthListSCIMUsersFilteredResponse{
		TotalResults: int(count),
		SCIMUsers:    scimUsers,
	}, nil
}

type AuthGetSCIMUserByEmailRequest struct {
	SCIMDirectoryID string
	Email           string
}

var ErrSCIMUserNotFound = errors.New("store: scim user not found")

func (s *Store) AuthGetSCIMUserByEmail(ctx context.Context, req *AuthGetSCIMUserByEmailRequest) (*ssoreadyv1.SCIMUser, error) {
	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMDirectoryID)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	qSCIMUser, err := s.q.AuthGetSCIMUserByEmail(ctx, queries.AuthGetSCIMUserByEmailParams{
		ScimDirectoryID: scimDirID,
		Email:           req.Email,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSCIMUserNotFound
		}

		return nil, fmt.Errorf("get scim user by email: %w", err)
	}

	return parseSCIMUser(qSCIMUser), nil
}

type AuthGetSCIMUserByEmailAndActiveRequest struct {
	SCIMDirectoryID string
	Email           string
	Active          bool
}

func (s *Store) AuthGetSCIMUserByEmailAndActive(ctx context.Context, req *AuthGetSCIMUserByEmailAndActiveRequest) (*ssoreadyv1.SCIMUser, error) {
	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMDirectoryID)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	qSCIMUser, err := s.q.AuthGetSCIMUserByEmailAndActive(ctx, queries.AuthGetSCIMUserByEmailAndActiveParams{
		ScimDirectoryID: scimDirID,
		Email:           req.Email,
		Active:          req.Active,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSCIMUserNotFound
		}

		return nil, fmt.Errorf("get scim user by email and active: %w", err)
	}

	return parseSCIMUser(qSCIMUser), nil
}

type AuthGetSCIMUserRequest struct {
	SCIMDirectoryID string
	SCIMUserID      string
}

func (s *Store) AuthGetSCIMUser(ctx context.Context, req *AuthGetSCIMUserRequest) (*ssoreadyv1.SCIMUser, error) {
	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMDirectoryID)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	scimUserID, err := idformat.SCIMUser.Parse(req.SCIMUserID)
	if err != nil {
		return nil, fmt.Errorf("parse scim user id: %w", err)
	}

	qSCIMUser, err := s.q.AuthGetSCIMUser(ctx, queries.AuthGetSCIMUserParams{
		ScimDirectoryID: scimDirID,
		ID:              scimUserID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSCIMUserNotFound
		}

		return nil, fmt.Errorf("get scim user: %w", err)
	}

	return parseSCIMUser(qSCIMUser), nil
}

type AuthGetSCIMUserIncludeDeletedRequest struct {
	SCIMDirectoryID string
	SCIMUserID      string
}

func (s *Store) AuthGetSCIMUserIncludeDeleted(ctx context.Context, req *AuthGetSCIMUserIncludeDeletedRequest) (*ssoreadyv1.SCIMUser, error) {
	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMDirectoryID)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	scimUserID, err := idformat.SCIMUser.Parse(req.SCIMUserID)
	if err != nil {
		return nil, fmt.Errorf("parse scim user id: %w", err)
	}

	qSCIMUser, err := s.q.AuthGetSCIMUserIncludeDeleted(ctx, queries.AuthGetSCIMUserIncludeDeletedParams{
		ScimDirectoryID: scimDirID,
		ID:              scimUserID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSCIMUserNotFound
		}
		return nil, fmt.Errorf("get scim user include deleted: %w", err)
	}

	return parseSCIMUser(qSCIMUser), nil
}

type AuthCreateSCIMUserRequest struct {
	SCIMUser *ssoreadyv1.SCIMUser
}

type AuthCreateSCIMUserResponse struct {
	SCIMUser *ssoreadyv1.SCIMUser
}

func (s *Store) AuthCreateSCIMUser(ctx context.Context, req *AuthCreateSCIMUserRequest) (*AuthCreateSCIMUserResponse, error) {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("tx: %w", err)
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMUser.ScimDirectoryId)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	attrs, err := json.Marshal(req.SCIMUser.Attributes.AsMap())
	if err != nil {
		panic(fmt.Errorf("marshal scim user attributes: %w", err))
	}

	qSCIMUser, err := q.AuthUpsertSCIMUser(ctx, queries.AuthUpsertSCIMUserParams{
		ID:              uuid.New(),
		ScimDirectoryID: scimDirID,
		Email:           req.SCIMUser.Email,
		Deleted:         false,
		Attributes:      attrs,
	})
	if err != nil {
		return nil, fmt.Errorf("create scim user: %w", err)
	}

	if err := commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &AuthCreateSCIMUserResponse{
		SCIMUser: parseSCIMUser(qSCIMUser),
	}, nil
}

type AuthUpdateSCIMUserRequest struct {
	SCIMUser *ssoreadyv1.SCIMUser
}

type AuthUpdateSCIMUserResponse struct {
	SCIMUser *ssoreadyv1.SCIMUser
}

func (s *Store) AuthUpdateSCIMUser(ctx context.Context, req *AuthUpdateSCIMUserRequest) (*AuthUpdateSCIMUserResponse, error) {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("tx: %w", err)
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMUser.ScimDirectoryId)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	scimUserID, err := idformat.SCIMUser.Parse(req.SCIMUser.Id)
	if err != nil {
		return nil, fmt.Errorf("parse scim user id: %w", err)
	}

	attrs, err := json.Marshal(req.SCIMUser.Attributes.AsMap())
	if err != nil {
		panic(fmt.Errorf("marshal scim user attributes: %w", err))
	}

	qSCIMUser, err := q.AuthUpdateSCIMUser(ctx, queries.AuthUpdateSCIMUserParams{
		ID:              scimUserID,
		ScimDirectoryID: scimDirID,
		Email:           req.SCIMUser.Email,
		Attributes:      attrs,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSCIMUserNotFound
		}
		return nil, fmt.Errorf("update scim user: %w", err)
	}

	if err := commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &AuthUpdateSCIMUserResponse{
		SCIMUser: parseSCIMUser(qSCIMUser),
	}, nil
}

type AuthUpdateSCIMUserEmailRequest struct {
	SCIMDirectoryID string
	SCIMUserID      string
	Email           string
}

func (s *Store) AuthUpdateSCIMUserEmail(ctx context.Context, req *AuthUpdateSCIMUserEmailRequest) error {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return fmt.Errorf("tx: %w", err)
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMDirectoryID)
	if err != nil {
		return fmt.Errorf("parse scim directory id: %w", err)
	}

	scimUserID, err := idformat.SCIMUser.Parse(req.SCIMUserID)
	if err != nil {
		return fmt.Errorf("parse scim user id: %w", err)
	}

	// check that the user belongs to the scim dir
	if _, err := q.AuthUpdateSCIMUserEmail(ctx, queries.AuthUpdateSCIMUserEmailParams{
		ScimDirectoryID: scimDirID,
		ID:              scimUserID,
		Email:           req.Email,
	}); err != nil {
		return fmt.Errorf("update scim user email: %w", err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}

type AuthDeleteSCIMUserRequest struct {
	SCIMDirectoryID string
	SCIMUserID      string
}

func (s *Store) AuthDeleteSCIMUser(ctx context.Context, req *AuthDeleteSCIMUserRequest) error {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return fmt.Errorf("tx: %w", err)
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMDirectoryID)
	if err != nil {
		return fmt.Errorf("parse scim directory id: %w", err)
	}

	scimUserID, err := idformat.SCIMUser.Parse(req.SCIMUserID)
	if err != nil {
		return fmt.Errorf("parse scim user id: %w: %w", ErrBadSCIMUserID, err)
	}

	// check that the user belongs to the scim dir
	if _, err := q.AuthGetSCIMUser(ctx, queries.AuthGetSCIMUserParams{
		ScimDirectoryID: scimDirID,
		ID:              scimUserID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSCIMUserNotFound
		}
		return fmt.Errorf("get scim user: %w", err)
	}

	if _, err := q.AuthMarkSCIMUserDeleted(ctx, scimUserID); err != nil {
		return fmt.Errorf("mark scim user deleted: %w", err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}

type AuthListSCIMGroupsFilteredRequest struct {
	SCIMDirectoryID string
	Filter          string
	StartIndex      int
	Count           int // Per RFC 7644 3.4.2.4: desired max results per page. 0 = return only totalResults, -1 = use default
}

type AuthListSCIMGroupsFilteredResponse struct {
	TotalResults int
	SCIMGroups   []*ssoreadyv1.SCIMGroup
}

func (s *Store) AuthListSCIMGroupsFiltered(ctx context.Context, req *AuthListSCIMGroupsFilteredRequest) (*AuthListSCIMGroupsFilteredResponse, error) {
	var scimDirID uuid.UUID
	var err error
	scimDirID, err = idformat.SCIMDirectory.Parse(req.SCIMDirectoryID)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	// Parse the SCIM filter to squirrel conditions
	parsedFilter, err := scimfilter.ParseToSquirrel(req.Filter, scimfilter.ResourceTypeGroup)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSCIMFilter, err)
	}

	// Build base query with squirrel
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	// Count query
	countBuilder := psql.Select("count(*)").From("scim_groups").
		Where(sq.Eq{"scim_directory_id": scimDirID}).
		Where(sq.Eq{"deleted": false})
	if parsedFilter.Where != nil {
		countBuilder = countBuilder.Where(parsedFilter.Where)
	}

	countSQL, countArgs, err := countBuilder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build count query: %w", err)
	}

	var count int64
	if err := s.db.QueryRow(ctx, countSQL, countArgs...).Scan(&count); err != nil {
		return nil, fmt.Errorf("count filtered scim groups: %w", err)
	}

	// Per RFC 7644 3.4.2.4: count=0 means return only totalResults
	if req.Count == 0 {
		return &AuthListSCIMGroupsFilteredResponse{
			TotalResults: int(count),
			SCIMGroups:   nil,
		}, nil
	}

	// Determine effective limit: negative means use default, otherwise cap at max
	limit := DefaultSCIMPageSize
	if req.Count > 0 {
		limit = min(req.Count, MaxSCIMPageSize)
	}

	// List query
	listBuilder := psql.Select("id", "scim_directory_id", "display_name", "deleted", "attributes").
		From("scim_groups").
		Where(sq.Eq{"scim_directory_id": scimDirID}).
		Where(sq.Eq{"deleted": false}).
		OrderBy("id").
		Offset(uint64(req.StartIndex)).
		Limit(uint64(limit))
	if parsedFilter.Where != nil {
		listBuilder = listBuilder.Where(parsedFilter.Where)
	}

	listSQL, listArgs, err := listBuilder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build list query: %w", err)
	}

	rows, err := s.db.Query(ctx, listSQL, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("list filtered scim groups: %w", err)
	}
	defer rows.Close()

	var scimGroups []*ssoreadyv1.SCIMGroup
	for rows.Next() {
		var qGroup queries.ScimGroup
		if err := rows.Scan(&qGroup.ID, &qGroup.ScimDirectoryID, &qGroup.DisplayName, &qGroup.Deleted, &qGroup.Attributes); err != nil {
			return nil, fmt.Errorf("scan scim group: %w", err)
		}
		scimGroups = append(scimGroups, parseSCIMGroup(qGroup))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scim groups: %w", err)
	}

	return &AuthListSCIMGroupsFilteredResponse{
		TotalResults: int(count),
		SCIMGroups:   scimGroups,
	}, nil
}

type AuthGetSCIMGroupRequest struct {
	SCIMDirectoryID string
	SCIMGroupID     string
}

var ErrSCIMGroupNotFound = errors.New("store: scim group not found")
var ErrBadSCIMGroupID = errors.New("bad scim group id")

func (s *Store) AuthGetSCIMGroup(ctx context.Context, req *AuthGetSCIMGroupRequest) (*ssoreadyv1.SCIMGroup, error) {
	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMDirectoryID)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	scimGroupID, err := idformat.SCIMGroup.Parse(req.SCIMGroupID)
	if err != nil {
		return nil, fmt.Errorf("parse scim group id: %w", err)
	}

	qSCIMGroup, err := s.q.AuthGetSCIMGroup(ctx, queries.AuthGetSCIMGroupParams{
		ScimDirectoryID: scimDirID,
		ID:              scimGroupID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSCIMGroupNotFound
		}
		return nil, fmt.Errorf("get scim group: %w", err)
	}

	return parseSCIMGroup(qSCIMGroup), nil
}

type AuthCreateSCIMGroupRequest struct {
	SCIMGroup         *ssoreadyv1.SCIMGroup
	MemberSCIMUserIDs []string
}

type AuthCreateSCIMGroupResponse struct {
	SCIMGroup         *ssoreadyv1.SCIMGroup
	MemberSCIMUserIDs []string
}

func (s *Store) AuthCreateSCIMGroup(ctx context.Context, req *AuthCreateSCIMGroupRequest) (*AuthCreateSCIMGroupResponse, error) {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("tx: %w", err)
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMGroup.ScimDirectoryId)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	// check every member user belongs to same directory as group does
	var scimUserIDs []uuid.UUID
	for _, scimUserID := range req.MemberSCIMUserIDs {
		scimUserID, err := idformat.SCIMUser.Parse(scimUserID)
		if err != nil {
			return nil, fmt.Errorf("parse scim user id: %w", err)
		}

		if _, err := q.AuthGetSCIMUser(ctx, queries.AuthGetSCIMUserParams{
			ScimDirectoryID: scimDirID,
			ID:              scimUserID,
		}); err != nil {
			return nil, fmt.Errorf("get scim user: %w", err)
		}

		scimUserIDs = append(scimUserIDs, scimUserID)
	}

	attrs, err := json.Marshal(req.SCIMGroup.Attributes.AsMap())
	if err != nil {
		panic(fmt.Errorf("marshal scim group attributes: %w", err))
	}

	qSCIMGroup, err := q.AuthCreateSCIMGroup(ctx, queries.AuthCreateSCIMGroupParams{
		ID:              uuid.New(),
		ScimDirectoryID: scimDirID,
		DisplayName:     req.SCIMGroup.DisplayName,
		Attributes:      attrs,
		Deleted:         false,
	})
	if err != nil {
		return nil, fmt.Errorf("create scim group: %w", err)
	}

	for _, scimUserID := range scimUserIDs {
		if err := q.AuthUpsertSCIMUserGroupMembership(ctx, queries.AuthUpsertSCIMUserGroupMembershipParams{
			ID:              uuid.New(),
			ScimDirectoryID: scimDirID,
			ScimUserID:      scimUserID,
			ScimGroupID:     qSCIMGroup.ID,
		}); err != nil {
			return nil, fmt.Errorf("create scim user group membership: %w", err)
		}
	}

	if err := commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &AuthCreateSCIMGroupResponse{
		SCIMGroup:         parseSCIMGroup(qSCIMGroup),
		MemberSCIMUserIDs: req.MemberSCIMUserIDs,
	}, nil
}

type AuthUpdateSCIMGroupRequest struct {
	SCIMGroup         *ssoreadyv1.SCIMGroup
	MemberSCIMUserIDs []string
}

type AuthUpdateSCIMGroupResponse struct {
	SCIMGroup         *ssoreadyv1.SCIMGroup
	MemberSCIMUserIDs []string
}

func (s *Store) AuthUpdateSCIMGroup(ctx context.Context, req *AuthUpdateSCIMGroupRequest) (*AuthUpdateSCIMGroupResponse, error) {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("tx: %w", err)
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMGroup.ScimDirectoryId)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	scimGroupID, err := idformat.SCIMGroup.Parse(req.SCIMGroup.Id)
	if err != nil {
		return nil, fmt.Errorf("parse scim group id: %w", err)
	}

	// authz check
	if _, err := q.AuthGetSCIMGroup(ctx, queries.AuthGetSCIMGroupParams{
		ScimDirectoryID: scimDirID,
		ID:              scimGroupID,
	}); err != nil {
		return nil, fmt.Errorf("get scim group: %w", err)
	}

	// check every member user belongs to same directory as group does
	var scimUserIDs []uuid.UUID
	for _, scimUserID := range req.MemberSCIMUserIDs {
		scimUserID, err := idformat.SCIMUser.Parse(scimUserID)
		if err != nil {
			return nil, fmt.Errorf("parse scim user id: %w", err)
		}

		if _, err := q.AuthGetSCIMUserIncludeDeleted(ctx, queries.AuthGetSCIMUserIncludeDeletedParams{
			ScimDirectoryID: scimDirID,
			ID:              scimUserID,
		}); err != nil {
			return nil, fmt.Errorf("get scim user: %w", err)
		}

		scimUserIDs = append(scimUserIDs, scimUserID)
	}

	attrs, err := json.Marshal(req.SCIMGroup.Attributes.AsMap())
	if err != nil {
		panic(fmt.Errorf("marshal scim group attributes: %w", err))
	}

	qSCIMGroup, err := q.AuthUpdateSCIMGroup(ctx, queries.AuthUpdateSCIMGroupParams{
		ID:          scimGroupID,
		DisplayName: req.SCIMGroup.DisplayName,
		Attributes:  attrs,
	})
	if err != nil {
		return nil, fmt.Errorf("create scim group: %w", err)
	}

	if err := q.AuthClearSCIMGroupMembers(ctx, scimGroupID); err != nil {
		return nil, fmt.Errorf("clear scim group members: %w", err)
	}

	for _, scimUserID := range scimUserIDs {
		if err := q.AuthUpsertSCIMUserGroupMembership(ctx, queries.AuthUpsertSCIMUserGroupMembershipParams{
			ID:              uuid.New(),
			ScimDirectoryID: scimDirID,
			ScimUserID:      scimUserID,
			ScimGroupID:     qSCIMGroup.ID,
		}); err != nil {
			return nil, fmt.Errorf("create scim user group membership: %w", err)
		}
	}

	if err := commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return &AuthUpdateSCIMGroupResponse{
		SCIMGroup:         parseSCIMGroup(qSCIMGroup),
		MemberSCIMUserIDs: req.MemberSCIMUserIDs,
	}, nil
}

func (s *Store) AuthUpdateSCIMGroupDisplayName(ctx context.Context, req *ssoreadyv1.SCIMGroup) error {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return fmt.Errorf("tx: %w", err)
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.ScimDirectoryId)
	if err != nil {
		return fmt.Errorf("parse scim directory id: %w", err)
	}

	scimGroupID, err := idformat.SCIMGroup.Parse(req.Id)
	if err != nil {
		return fmt.Errorf("parse scim group id: %w", err)
	}

	// authz check
	if _, err := q.AuthGetSCIMGroup(ctx, queries.AuthGetSCIMGroupParams{
		ScimDirectoryID: scimDirID,
		ID:              scimGroupID,
	}); err != nil {
		return fmt.Errorf("get scim group: %w", err)
	}

	if _, err := q.AuthUpdateSCIMGroupDisplayName(ctx, queries.AuthUpdateSCIMGroupDisplayNameParams{
		ID:          scimGroupID,
		DisplayName: req.DisplayName,
	}); err != nil {
		return fmt.Errorf("update scim group display name: %w", err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}

type AuthAddSCIMGroupMemberRequest struct {
	SCIMGroup   *ssoreadyv1.SCIMGroup
	SCIMUserIDs []string
}

var ErrBadSCIMUserID = errors.New("bad scim user id")

func (s *Store) AuthAddSCIMGroupMember(ctx context.Context, req *AuthAddSCIMGroupMemberRequest) error {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return fmt.Errorf("tx: %w", err)
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMGroup.ScimDirectoryId)
	if err != nil {
		return fmt.Errorf("parse scim directory id: %w", err)
	}

	scimGroupID, err := idformat.SCIMGroup.Parse(req.SCIMGroup.Id)
	if err != nil {
		return fmt.Errorf("parse scim group id: %w", err)
	}

	// authz check
	if _, err := q.AuthGetSCIMGroup(ctx, queries.AuthGetSCIMGroupParams{
		ScimDirectoryID: scimDirID,
		ID:              scimGroupID,
	}); err != nil {
		return fmt.Errorf("get scim group: %w", err)
	}

	for _, rawUserID := range req.SCIMUserIDs {
		scimUserID, err := idformat.SCIMUser.Parse(rawUserID)
		if err != nil {
			return fmt.Errorf("parse scim user id: %w: %w", ErrBadSCIMUserID, err)
		}

		if _, err := q.AuthGetSCIMUserIncludeDeleted(ctx, queries.AuthGetSCIMUserIncludeDeletedParams{
			ScimDirectoryID: scimDirID,
			ID:              scimUserID,
		}); err != nil {
			return fmt.Errorf("get scim user: %w", err)
		}

		if err := q.AuthUpsertSCIMUserGroupMembership(ctx, queries.AuthUpsertSCIMUserGroupMembershipParams{
			ID:              uuid.New(),
			ScimDirectoryID: scimDirID,
			ScimUserID:      scimUserID,
			ScimGroupID:     scimGroupID,
		}); err != nil {
			return fmt.Errorf("create scim group membership: %w", err)
		}
	}

	if err := commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

type AuthRemoveSCIMGroupMemberRequest struct {
	SCIMGroup   *ssoreadyv1.SCIMGroup
	SCIMUserIDs []string
}

func (s *Store) AuthRemoveSCIMGroupMember(ctx context.Context, req *AuthRemoveSCIMGroupMemberRequest) error {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return fmt.Errorf("tx: %w", err)
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMGroup.ScimDirectoryId)
	if err != nil {
		return fmt.Errorf("parse scim directory id: %w", err)
	}

	scimGroupID, err := idformat.SCIMGroup.Parse(req.SCIMGroup.Id)
	if err != nil {
		return fmt.Errorf("parse scim group id: %w", err)
	}

	// authz check
	if _, err := q.AuthGetSCIMGroup(ctx, queries.AuthGetSCIMGroupParams{
		ScimDirectoryID: scimDirID,
		ID:              scimGroupID,
	}); err != nil {
		return fmt.Errorf("get scim group: %w", err)
	}

	for _, rawUserID := range req.SCIMUserIDs {
		scimUserID, err := idformat.SCIMUser.Parse(rawUserID)
		if err != nil {
			return fmt.Errorf("parse scim user id: %w: %w", ErrBadSCIMUserID, err)
		}

		if _, err := q.AuthGetSCIMUserIncludeDeleted(ctx, queries.AuthGetSCIMUserIncludeDeletedParams{
			ScimDirectoryID: scimDirID,
			ID:              scimUserID,
		}); err != nil {
			return fmt.Errorf("get scim user: %w", err)
		}

		if err := q.AuthDeleteSCIMUserGroupMembership(ctx, queries.AuthDeleteSCIMUserGroupMembershipParams{
			ScimDirectoryID: scimDirID,
			ScimUserID:      scimUserID,
			ScimGroupID:     scimGroupID,
		}); err != nil {
			return fmt.Errorf("delete scim group membership: %w", err)
		}
	}

	if err := commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

type AuthDeleteSCIMGroupRequest struct {
	SCIMDirectoryID string
	SCIMGroupID     string
}

func (s *Store) AuthDeleteSCIMGroup(ctx context.Context, req *AuthDeleteSCIMGroupRequest) error {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return fmt.Errorf("tx: %w", err)
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.SCIMDirectoryID)
	if err != nil {
		return fmt.Errorf("parse scim directory id: %w", err)
	}

	scimGroupID, err := idformat.SCIMGroup.Parse(req.SCIMGroupID)
	if err != nil {
		return fmt.Errorf("parse scim group id: %w: %w", ErrBadSCIMGroupID, err)
	}

	// check that the group belongs to the scim dir
	if _, err := q.AuthGetSCIMGroup(ctx, queries.AuthGetSCIMGroupParams{
		ScimDirectoryID: scimDirID,
		ID:              scimGroupID,
	}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSCIMGroupNotFound
		}
		return fmt.Errorf("get scim group: %w", err)
	}

	if _, err := q.AuthMarkSCIMGroupDeleted(ctx, scimGroupID); err != nil {
		return fmt.Errorf("mark scim group deleted: %w", err)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}

func parseSCIMUser(qSCIMUser queries.ScimUser) *ssoreadyv1.SCIMUser {
	var attrs map[string]any
	if err := json.Unmarshal(qSCIMUser.Attributes, &attrs); err != nil {
		panic(fmt.Errorf("unmarshal scim user attributes: %w", err))
	}

	attrsStruct, err := structpb.NewStruct(attrs)
	if err != nil {
		panic(fmt.Errorf("build struct from scim user attributes: %w", err))
	}

	return &ssoreadyv1.SCIMUser{
		Id:              idformat.SCIMUser.Format(qSCIMUser.ID),
		ScimDirectoryId: idformat.SCIMDirectory.Format(qSCIMUser.ScimDirectoryID),
		Email:           qSCIMUser.Email,
		Deleted:         qSCIMUser.Deleted,
		Attributes:      attrsStruct,
	}
}

func parseSCIMGroup(qSCIMGroup queries.ScimGroup) *ssoreadyv1.SCIMGroup {
	var attrs map[string]any
	if err := json.Unmarshal(qSCIMGroup.Attributes, &attrs); err != nil {
		panic(fmt.Errorf("unmarshal scim group attributes: %w", err))
	}

	attrsStruct, err := structpb.NewStruct(attrs)
	if err != nil {
		panic(fmt.Errorf("build struct from scim group attributes: %w", err))
	}

	return &ssoreadyv1.SCIMGroup{
		Id:              idformat.SCIMGroup.Format(qSCIMGroup.ID),
		ScimDirectoryId: idformat.SCIMDirectory.Format(qSCIMGroup.ScimDirectoryID),
		DisplayName:     qSCIMGroup.DisplayName,
		Attributes:      attrsStruct,
		Deleted:         qSCIMGroup.Deleted,
	}
}

func (s *Store) AuthCreateSCIMRequest(ctx context.Context, req *ssoreadyv1.SCIMRequest) (*ssoreadyv1.SCIMRequest, error) {
	scimDirID, err := idformat.SCIMDirectory.Parse(req.ScimDirectoryId)
	if err != nil {
		return nil, fmt.Errorf("parse scim directory id: %w", err)
	}

	var requestMethod queries.ScimRequestHttpMethod
	switch req.HttpRequestMethod {
	case ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_GET:
		requestMethod = queries.ScimRequestHttpMethodGet
	case ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_POST:
		requestMethod = queries.ScimRequestHttpMethodPost
	case ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_PUT:
		requestMethod = queries.ScimRequestHttpMethodPut
	case ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_PATCH:
		requestMethod = queries.ScimRequestHttpMethodPatch
	case ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_DELETE:
		requestMethod = queries.ScimRequestHttpMethodDelete
	}

	requestBody, err := json.Marshal(req.HttpRequestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request body: %w", err)
	}

	var status queries.ScimRequestHttpStatus
	switch req.HttpResponseStatus {
	case ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_200:
		status = queries.ScimRequestHttpStatus200
	case ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_201:
		status = queries.ScimRequestHttpStatus201
	case ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_204:
		status = queries.ScimRequestHttpStatus204
	case ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_400:
		status = queries.ScimRequestHttpStatus400
	case ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_401:
		status = queries.ScimRequestHttpStatus401
	case ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_404:
		status = queries.ScimRequestHttpStatus404
	}

	responseBody, err := json.Marshal(req.HttpResponseBody)
	if err != nil {
		return nil, fmt.Errorf("marshal response body: %w", err)
	}

	var badBearerToken bool
	if _, ok := req.Error.(*ssoreadyv1.SCIMRequest_BadBearerToken); ok {
		badBearerToken = true
	}

	var badUsername *string
	if e, ok := req.Error.(*ssoreadyv1.SCIMRequest_BadUsername); ok {
		badUsername = &e.BadUsername
	}

	var emailOutsideOrganizationDomains *string
	if e, ok := req.Error.(*ssoreadyv1.SCIMRequest_EmailOutsideOrganizationDomains); ok {
		emailOutsideOrganizationDomains = &e.EmailOutsideOrganizationDomains
	}

	qSCIMRequest, err := s.q.AuthCreateSCIMRequest(ctx, queries.AuthCreateSCIMRequestParams{
		ID:                                   uuid.Must(uuid.NewV7()),
		ScimDirectoryID:                      scimDirID,
		Timestamp:                            req.Timestamp.AsTime(),
		HttpRequestUrl:                       req.HttpRequestUrl,
		HttpRequestMethod:                    requestMethod,
		HttpRequestBody:                      requestBody,
		HttpResponseStatus:                   status,
		HttpResponseBody:                     responseBody,
		ErrorBadBearerToken:                  badBearerToken,
		ErrorBadUsername:                     badUsername,
		ErrorEmailOutsideOrganizationDomains: emailOutsideOrganizationDomains,
	})
	if err != nil {
		return nil, fmt.Errorf("create scim request: %w", err)
	}

	return parseSCIMRequest(qSCIMRequest), nil
}

func parseSCIMRequest(qSCIMRequest queries.ScimRequest) *ssoreadyv1.SCIMRequest {
	var requestMethod ssoreadyv1.SCIMRequestHTTPMethod
	switch qSCIMRequest.HttpRequestMethod {
	case queries.ScimRequestHttpMethodGet:
		requestMethod = ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_GET
	case queries.ScimRequestHttpMethodPost:
		requestMethod = ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_POST
	case queries.ScimRequestHttpMethodPut:
		requestMethod = ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_PUT
	case queries.ScimRequestHttpMethodPatch:
		requestMethod = ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_PATCH
	case queries.ScimRequestHttpMethodDelete:
		requestMethod = ssoreadyv1.SCIMRequestHTTPMethod_SCIM_REQUEST_HTTP_METHOD_DELETE
	}

	var status ssoreadyv1.SCIMRequestHTTPStatus
	switch qSCIMRequest.HttpResponseStatus {
	case queries.ScimRequestHttpStatus200:
		status = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_200
	case queries.ScimRequestHttpStatus201:
		status = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_201
	case queries.ScimRequestHttpStatus204:
		status = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_204
	case queries.ScimRequestHttpStatus400:
		status = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_400
	case queries.ScimRequestHttpStatus401:
		status = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_401
	case queries.ScimRequestHttpStatus404:
		status = ssoreadyv1.SCIMRequestHTTPStatus_SCIM_REQUEST_HTTP_STATUS_404
	}

	var requestBody map[string]any
	if err := json.Unmarshal(qSCIMRequest.HttpRequestBody, &requestBody); err != nil {
		panic(fmt.Errorf("unmarshal request body: %w", err))
	}

	requestBodyStruct, err := structpb.NewStruct(requestBody)
	if err != nil {
		panic(fmt.Errorf("struct from request body: %w", err))
	}

	var responseBody map[string]any
	if err := json.Unmarshal(qSCIMRequest.HttpResponseBody, &responseBody); err != nil {
		panic(fmt.Errorf("unmarshal response body: %w", err))
	}

	responseBodyStruct, err := structpb.NewStruct(responseBody)
	if err != nil {
		panic(fmt.Errorf("struct from response body: %w", err))
	}

	res := &ssoreadyv1.SCIMRequest{
		Id:                 idformat.SCIMRequest.Format(qSCIMRequest.ID),
		ScimDirectoryId:    idformat.SCIMDirectory.Format(qSCIMRequest.ScimDirectoryID),
		Timestamp:          timestamppb.New(qSCIMRequest.Timestamp),
		HttpRequestUrl:     qSCIMRequest.HttpRequestUrl,
		HttpRequestMethod:  requestMethod,
		HttpRequestBody:    requestBodyStruct,
		HttpResponseStatus: status,
		HttpResponseBody:   responseBodyStruct,
		Error:              nil,
	}

	if qSCIMRequest.ErrorBadBearerToken {
		res.Error = &ssoreadyv1.SCIMRequest_BadBearerToken{BadBearerToken: &emptypb.Empty{}}
	}

	if qSCIMRequest.ErrorBadUsername != nil {
		res.Error = &ssoreadyv1.SCIMRequest_BadUsername{BadUsername: *qSCIMRequest.ErrorBadUsername}
	}

	if qSCIMRequest.ErrorEmailOutsideOrganizationDomains != nil {
		res.Error = &ssoreadyv1.SCIMRequest_EmailOutsideOrganizationDomains{EmailOutsideOrganizationDomains: *qSCIMRequest.ErrorEmailOutsideOrganizationDomains}
	}

	return res
}

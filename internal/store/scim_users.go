package store

import (
	"context"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/sebdroid/ssosebby/internal/authn"
	ssoreadyv1 "github.com/sebdroid/ssosebby/internal/gen/ssoready/v1"
	"github.com/sebdroid/ssosebby/internal/scimfilter"
	"github.com/sebdroid/ssosebby/internal/store/idformat"
	"github.com/sebdroid/ssosebby/internal/store/queries"
)

func (s *Store) AppListSCIMUsers(ctx context.Context, req *ssoreadyv1.AppListSCIMUsersRequest) (*ssoreadyv1.AppListSCIMUsersResponse, error) {
	tx, q, _, rollback, err := s.tx(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback()

	scimDirID, err := idformat.SCIMDirectory.Parse(req.ScimDirectoryId)
	if err != nil {
		return nil, err
	}

	// idor check
	if _, err = q.GetSCIMDirectory(ctx, queries.GetSCIMDirectoryParams{
		AppOrganizationID: authn.AppOrgID(ctx),
		ID:                scimDirID,
	}); err != nil {
		return nil, err
	}

	var startID uuid.UUID
	if err := s.pageEncoder.Unmarshal(req.PageToken, &startID); err != nil {
		return nil, err
	}

	// If no filter is provided, use the existing static queries
	if req.Filter == "" {
		limit := 10
		var qSCIMUsers []queries.ScimUser
		if req.ScimGroupId == "" {
			qSCIMUsers, err = q.ListSCIMUsers(ctx, queries.ListSCIMUsersParams{
				ScimDirectoryID: scimDirID,
				ID:              startID,
				Limit:           int32(limit + 1),
			})
			if err != nil {
				return nil, err
			}
		} else {
			scimGroupID, err := idformat.SCIMGroup.Parse(req.ScimGroupId)
			if err != nil {
				return nil, fmt.Errorf("parse scim group id: %w", err)
			}

			qSCIMUsers, err = q.ListSCIMUsersInSCIMGroup(ctx, queries.ListSCIMUsersInSCIMGroupParams{
				ScimDirectoryID: scimDirID,
				ID:              startID,
				Limit:           int32(limit + 1),
				ScimGroupID:     scimGroupID,
			})
			if err != nil {
				return nil, err
			}
		}

		return s.appListSCIMUsersResponse(qSCIMUsers, limit)
	}

	// Dynamic query path: filter is set
	parsedFilter, err := scimfilter.ParseToSquirrel(req.Filter, scimfilter.ResourceTypeUser)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSCIMFilter, err)
	}

	limit := 10
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	builder := psql.Select("id", "scim_directory_id", "email", "deleted", "attributes").
		From("scim_users").
		Where("scim_directory_id = ?", scimDirID).
		Where("id >= ?", startID).
		OrderBy("id").
		Limit(uint64(limit + 1))

	if parsedFilter.Where != nil {
		builder = builder.Where(parsedFilter.Where)
	}

	if req.ScimGroupId != "" {
		scimGroupID, err := idformat.SCIMGroup.Parse(req.ScimGroupId)
		if err != nil {
			return nil, fmt.Errorf("parse scim group id: %w", err)
		}
		builder = builder.Where(
			"EXISTS (SELECT 1 FROM scim_user_group_memberships WHERE scim_group_id = ? AND scim_user_id = scim_users.id)",
			scimGroupID,
		)
	}

	query, args, err := builder.ToSql()
	if err != nil {
		return nil, fmt.Errorf("build query: %w", err)
	}

	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list filtered scim users: %w", err)
	}
	defer rows.Close()

	var qSCIMUsers []queries.ScimUser
	for rows.Next() {
		var u queries.ScimUser
		if err := rows.Scan(&u.ID, &u.ScimDirectoryID, &u.Email, &u.Deleted, &u.Attributes); err != nil {
			return nil, fmt.Errorf("scan scim user: %w", err)
		}
		qSCIMUsers = append(qSCIMUsers, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scim users: %w", err)
	}

	return s.appListSCIMUsersResponse(qSCIMUsers, limit)
}

func (s *Store) appListSCIMUsersResponse(qSCIMUsers []queries.ScimUser, limit int) (*ssoreadyv1.AppListSCIMUsersResponse, error) {
	var scimUsers []*ssoreadyv1.SCIMUser
	for _, qSCIMUser := range qSCIMUsers {
		scimUsers = append(scimUsers, parseSCIMUser(qSCIMUser))
	}

	var nextPageToken string
	if len(scimUsers) == limit+1 {
		nextPageToken = s.pageEncoder.Marshal(qSCIMUsers[limit].ID)
		scimUsers = scimUsers[:limit]
	}

	return &ssoreadyv1.AppListSCIMUsersResponse{
		ScimUsers:     scimUsers,
		NextPageToken: nextPageToken,
	}, nil
}

// AppGetSCIMGroupsForUser returns all non-deleted groups a user belongs to.
func (s *Store) AppGetSCIMGroupsForUser(ctx context.Context, scimUserID string) ([]*ssoreadyv1.SCIMGroup, error) {
	userID, err := idformat.SCIMUser.Parse(scimUserID)
	if err != nil {
		return nil, fmt.Errorf("parse scim user id: %w", err)
	}

	qGroups, err := s.q.AppListSCIMGroupsForUser(ctx, queries.AppListSCIMGroupsForUserParams{
		ScimUserID:        userID,
		AppOrganizationID: authn.AppOrgID(ctx),
	})
	if err != nil {
		return nil, fmt.Errorf("list groups for user: %w", err)
	}

	var groups []*ssoreadyv1.SCIMGroup
	for _, qg := range qGroups {
		groups = append(groups, parseSCIMGroup(qg))
	}
	return groups, nil
}

func (s *Store) AppGetSCIMUser(ctx context.Context, req *ssoreadyv1.AppGetSCIMUserRequest) (*ssoreadyv1.SCIMUser, error) {
	scimUserID, err := idformat.SCIMUser.Parse(req.Id)
	if err != nil {
		return nil, err
	}

	qSCIMUser, err := s.q.AppGetSCIMUser(ctx, queries.AppGetSCIMUserParams{
		AppOrganizationID: authn.AppOrgID(ctx),
		ID:                scimUserID,
	})
	if err != nil {
		return nil, fmt.Errorf("get scim user: %w", err)
	}

	return parseSCIMUser(qSCIMUser), nil
}

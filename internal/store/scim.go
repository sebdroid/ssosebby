package store

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sebdroid/ssosebby/internal/authn"
	ssoreadyv1 "github.com/sebdroid/ssosebby/internal/gen/ssoready/v1"
	"github.com/sebdroid/ssosebby/internal/scimfilter"
	"github.com/sebdroid/ssosebby/internal/store/idformat"
	"github.com/sebdroid/ssosebby/internal/store/queries"
)

func (s *Store) ListSCIMUsers(ctx context.Context, req *ssoreadyv1.ListSCIMUsersRequest) (*ssoreadyv1.ListSCIMUsersResponse, error) {
	tx, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback()

	authnData := authn.FullContextData(ctx)
	if authnData.APIKey == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("api key authentication is required"))
	}

	envID, err := idformat.Environment.Parse(authnData.APIKey.EnvID)
	if err != nil {
		return nil, err
	}

	var scimDirID uuid.UUID
	if req.ScimDirectoryId != "" {
		scimDirID, err = idformat.SCIMDirectory.Parse(req.ScimDirectoryId)
		if err != nil {
			return nil, err
		}

		// check that scim dir belongs to env by making sure this query finds something
		if _, err := s.q.GetSCIMDirectoryByIDAndEnvironmentID(ctx, queries.GetSCIMDirectoryByIDAndEnvironmentIDParams{
			EnvironmentID: envID,
			ID:            scimDirID,
		}); err != nil {
			return nil, err
		}
	} else if req.OrganizationId != "" {
		orgID, err := idformat.Organization.Parse(req.OrganizationId)
		if err != nil {
			return nil, err
		}

		scimDirID, err = q.GetPrimarySCIMDirectoryIDByOrganizationID(ctx, queries.GetPrimarySCIMDirectoryIDByOrganizationIDParams{
			EnvironmentID: envID,
			ID:            orgID,
		})
		if err != nil {
			return nil, err
		}
	} else if req.OrganizationExternalId != "" {
		scimDirID, err = q.GetPrimarySCIMDirectoryIDByOrganizationExternalID(ctx, queries.GetPrimarySCIMDirectoryIDByOrganizationExternalIDParams{
			EnvironmentID: envID,
			ExternalID:    &req.OrganizationExternalId,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("bad organization_external_id: organization not found, or organization does not have a primary SCIM directory"))
			}
			return nil, err
		}
	} else {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("one of scim_directory_id, organization_id, or organization_external_id must be provided"))
	}

	var startID uuid.UUID
	if err := s.pageEncoder.Unmarshal(req.PageToken, &startID); err != nil {
		return nil, err
	}

	limit := 10

	if req.Filter == "" {
		var qSCIMUsers []queries.ScimUser
		if req.ScimGroupId != "" {
			scimGroupID, err := idformat.SCIMGroup.Parse(req.ScimGroupId)
			if err != nil {
				return nil, fmt.Errorf("parse scim group id: %w", err)
			}

			qSCIMUsers, err = s.q.ListSCIMUsersInSCIMGroup(ctx, queries.ListSCIMUsersInSCIMGroupParams{
				ScimDirectoryID: scimDirID,
				ID:              startID,
				Limit:           int32(limit + 1),
				ScimGroupID:     scimGroupID,
			})
			if err != nil {
				return nil, err
			}
		} else {
			qSCIMUsers, err = s.q.ListSCIMUsers(ctx, queries.ListSCIMUsersParams{
				ScimDirectoryID: scimDirID,
				ID:              startID,
				Limit:           int32(limit + 1),
			})
			if err != nil {
				return nil, err
			}
		}

		if err := commit(); err != nil {
			return nil, fmt.Errorf("commit: %w", err)
		}

		return s.listSCIMUsersResponse(qSCIMUsers, limit)
	}

	parsedFilter, err := scimfilter.ParseToSquirrel(req.Filter, scimfilter.ResourceTypeUser)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("%w: %v", ErrInvalidSCIMFilter, err))
	}

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

	if err := commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	return s.listSCIMUsersResponse(qSCIMUsers, limit)
}

func (s *Store) listSCIMUsersResponse(qSCIMUsers []queries.ScimUser, limit int) (*ssoreadyv1.ListSCIMUsersResponse, error) {
	var scimUsers []*ssoreadyv1.SCIMUser
	for _, qSCIMUser := range qSCIMUsers {
		scimUsers = append(scimUsers, parseSCIMUser(qSCIMUser))
	}

	var nextPageToken string
	if len(scimUsers) == limit+1 {
		nextPageToken = s.pageEncoder.Marshal(qSCIMUsers[limit].ID)
		scimUsers = scimUsers[:limit]
	}

	return &ssoreadyv1.ListSCIMUsersResponse{
		ScimUsers:     scimUsers,
		NextPageToken: nextPageToken,
	}, nil
}

func (s *Store) GetSCIMUser(ctx context.Context, req *ssoreadyv1.GetSCIMUserRequest) (*ssoreadyv1.GetSCIMUserResponse, error) {
	id, err := idformat.SCIMUser.Parse(req.Id)
	if err != nil {
		return nil, err
	}

	authnData := authn.FullContextData(ctx)
	if authnData.APIKey == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("api key authentication is required"))
	}

	envID, err := idformat.Environment.Parse(authnData.APIKey.EnvID)
	if err != nil {
		return nil, err
	}

	_, q, _, rollback, err := s.tx(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback()

	qSCIMUser, err := q.GetSCIMUser(ctx, queries.GetSCIMUserParams{
		EnvironmentID: envID,
		ID:            id,
	})
	if err != nil {
		return nil, err
	}

	qGroups, err := q.ListSCIMGroupsForUser(ctx, queries.ListSCIMGroupsForUserParams{
		ScimUserID:    id,
		EnvironmentID: envID,
	})
	if err != nil {
		return nil, fmt.Errorf("list groups for user: %w", err)
	}

	scimUser := parseSCIMUser(qSCIMUser)
	for _, qg := range qGroups {
		scimUser.Groups = append(scimUser.Groups, &ssoreadyv1.SCIMGroupRef{
			Id:          idformat.SCIMGroup.Format(qg.ID),
			DisplayName: qg.DisplayName,
		})
	}

	return &ssoreadyv1.GetSCIMUserResponse{ScimUser: scimUser}, nil
}

func (s *Store) ListSCIMGroups(ctx context.Context, req *ssoreadyv1.ListSCIMGroupsRequest) (*ssoreadyv1.ListSCIMGroupsResponse, error) {
	_, q, commit, rollback, err := s.tx(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback()

	authnData := authn.FullContextData(ctx)
	if authnData.APIKey == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("api key authentication is required"))
	}

	envID, err := idformat.Environment.Parse(authnData.APIKey.EnvID)
	if err != nil {
		return nil, err
	}

	var scimDirID uuid.UUID
	if req.ScimDirectoryId != "" {
		scimDirID, err = idformat.SCIMDirectory.Parse(req.ScimDirectoryId)
		if err != nil {
			return nil, err
		}

		// check that scim dir belongs to env by making sure this query finds something
		if _, err := s.q.GetSCIMDirectoryByIDAndEnvironmentID(ctx, queries.GetSCIMDirectoryByIDAndEnvironmentIDParams{
			EnvironmentID: envID,
			ID:            scimDirID,
		}); err != nil {
			return nil, err
		}
	} else if req.OrganizationId != "" {
		orgID, err := idformat.Organization.Parse(req.OrganizationId)
		if err != nil {
			return nil, err
		}

		scimDirID, err = q.GetPrimarySCIMDirectoryIDByOrganizationID(ctx, queries.GetPrimarySCIMDirectoryIDByOrganizationIDParams{
			EnvironmentID: envID,
			ID:            orgID,
		})
		if err != nil {
			return nil, err
		}
	} else if req.OrganizationExternalId != "" {
		scimDirID, err = q.GetPrimarySCIMDirectoryIDByOrganizationExternalID(ctx, queries.GetPrimarySCIMDirectoryIDByOrganizationExternalIDParams{
			EnvironmentID: envID,
			ExternalID:    &req.OrganizationExternalId,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("bad organization_external_id: organization not found, or organization does not have a primary SCIM directory"))
			}
			return nil, err
		}
	} else {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("one of scim_directory_id, organization_id, or organization_external_id must be provided"))
	}

	var startID uuid.UUID
	if err := s.pageEncoder.Unmarshal(req.PageToken, &startID); err != nil {
		return nil, err
	}

	limit := 10
	qSCIMGroups, err := s.q.ListSCIMGroups(ctx, queries.ListSCIMGroupsParams{
		ScimDirectoryID: scimDirID,
		ID:              startID,
		Limit:           int32(limit + 1),
	})
	if err != nil {
		return nil, err
	}

	if err := commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	var scimGroups []*ssoreadyv1.SCIMGroup
	for _, qSCIMgroup := range qSCIMGroups {
		scimGroups = append(scimGroups, parseSCIMGroup(qSCIMgroup))
	}

	var nextPageToken string
	if len(scimGroups) == limit+1 {
		nextPageToken = s.pageEncoder.Marshal(qSCIMGroups[limit].ID)
		scimGroups = scimGroups[:limit]
	}

	return &ssoreadyv1.ListSCIMGroupsResponse{
		ScimGroups:    scimGroups,
		NextPageToken: nextPageToken,
	}, nil
}

func (s *Store) GetSCIMGroup(ctx context.Context, req *ssoreadyv1.GetSCIMGroupRequest) (*ssoreadyv1.GetSCIMGroupResponse, error) {
	id, err := idformat.SCIMGroup.Parse(req.Id)
	if err != nil {
		return nil, err
	}

	authnData := authn.FullContextData(ctx)
	if authnData.APIKey == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("api key authentication is required"))
	}

	envID, err := idformat.Environment.Parse(authnData.APIKey.EnvID)
	if err != nil {
		return nil, err
	}

	_, q, _, rollback, err := s.tx(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback()

	qSCIMGroup, err := q.GetSCIMGroup(ctx, queries.GetSCIMGroupParams{
		EnvironmentID: envID,
		ID:            id,
	})
	if err != nil {
		return nil, err
	}

	return &ssoreadyv1.GetSCIMGroupResponse{ScimGroup: parseSCIMGroup(qSCIMGroup)}, nil
}

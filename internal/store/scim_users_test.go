package store

import (
	"testing"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/sebdroid/ssosebby/internal/scimfilter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildAppListSCIMUsersQuery replicates the dynamic query path from AppListSCIMUsers
// so we can test the generated SQL without needing a database connection.
func buildAppListSCIMUsersQuery(scimDirID, startID uuid.UUID, filter string, scimGroupID *uuid.UUID) (string, []any, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	builder := psql.Select("id", "scim_directory_id", "email", "deleted", "attributes").
		From("scim_users").
		Where(sq.Eq{"scim_directory_id": scimDirID}).
		Where(sq.GtOrEq{"id": startID}).
		OrderBy("id").
		Limit(11)

	if filter != "" {
		parsedFilter, err := scimfilter.ParseToSquirrel(filter, scimfilter.ResourceTypeUser)
		if err != nil {
			return "", nil, err
		}
		if parsedFilter.Where != nil {
			builder = builder.Where(parsedFilter.Where)
		}
	}

	if scimGroupID != nil {
		builder = builder.Where(
			"EXISTS (SELECT 1 FROM scim_user_group_memberships WHERE scim_group_id = ? AND scim_user_id = scim_users.id)",
			*scimGroupID,
		)
	}

	return builder.ToSql()
}

func TestAppListSCIMUsersQuery_FilterByEmail(t *testing.T) {
	dirID := uuid.New()
	startID := uuid.UUID{}

	query, args, err := buildAppListSCIMUsersQuery(dirID, startID, `userName eq "alice@example.com"`, nil)
	require.NoError(t, err)

	assert.Contains(t, query, "email = $")
	assert.Contains(t, args, "alice@example.com")
	assert.Contains(t, args, dirID.String())
}

func TestAppListSCIMUsersQuery_FilterByEmailValue(t *testing.T) {
	dirID := uuid.New()
	startID := uuid.UUID{}

	query, args, err := buildAppListSCIMUsersQuery(dirID, startID, `email.value eq "bob@example.com"`, nil)
	require.NoError(t, err)

	assert.Contains(t, query, "email = $")
	assert.Contains(t, args, "bob@example.com")
}

func TestAppListSCIMUsersQuery_FilterByActive(t *testing.T) {
	dirID := uuid.New()
	startID := uuid.UUID{}

	query, args, err := buildAppListSCIMUsersQuery(dirID, startID, `active eq true`, nil)
	require.NoError(t, err)

	assert.Contains(t, query, "(attributes->>'active')::boolean")
	assert.Contains(t, args, true)
}

func TestAppListSCIMUsersQuery_FilterWithGroupMembership(t *testing.T) {
	dirID := uuid.New()
	startID := uuid.UUID{}
	groupID := uuid.New()

	query, args, err := buildAppListSCIMUsersQuery(dirID, startID, `userName eq "alice@example.com"`, &groupID)
	require.NoError(t, err)

	assert.Contains(t, query, "email = $")
	assert.Contains(t, query, "EXISTS (SELECT 1 FROM scim_user_group_memberships")
	assert.Contains(t, args, "alice@example.com")
	assert.Contains(t, args, groupID)
}

func TestAppListSCIMUsersQuery_NoFilter(t *testing.T) {
	dirID := uuid.New()
	startID := uuid.UUID{}

	query, args, err := buildAppListSCIMUsersQuery(dirID, startID, "", nil)
	require.NoError(t, err)

	// Should only have base conditions: directory_id, startID, limit
	assert.Contains(t, query, "scim_directory_id = $")
	assert.NotContains(t, query, "email = $")
	assert.NotContains(t, query, "EXISTS")
	assert.Equal(t, 2, len(args)) // dirID and startID only
}

func TestAppListSCIMUsersQuery_InvalidFilter(t *testing.T) {
	dirID := uuid.New()
	startID := uuid.UUID{}

	_, _, err := buildAppListSCIMUsersQuery(dirID, startID, `not a valid filter!!!`, nil)
	assert.Error(t, err)
}

func TestAppListSCIMUsersQuery_CompoundFilter(t *testing.T) {
	dirID := uuid.New()
	startID := uuid.UUID{}

	query, args, err := buildAppListSCIMUsersQuery(dirID, startID, `userName eq "alice@example.com" and active eq true`, nil)
	require.NoError(t, err)

	assert.Contains(t, query, "email = $")
	assert.Contains(t, query, "(attributes->>'active')::boolean")
	assert.Contains(t, args, "alice@example.com")
	assert.Contains(t, args, true)
}

-- Add indexes for all SCIM filterable attributes
-- All indexes are partial (WHERE deleted = false) since we only query non-deleted resources
--
-- Note: The following are already covered:
--   - scim_users.email: unique constraint on (scim_directory_id, email)
--   - scim_users.id: primary key
--   - scim_users.active: indexed in migration 000054
--   - scim_groups.id: primary key

-- ============================================
-- SCIM Users indexes
-- ============================================

-- externalId - used by identity providers to correlate users
CREATE INDEX idx_scim_users_external_id ON scim_users (scim_directory_id, (attributes->>'externalId')) WHERE deleted = false;

-- displayName - user display name filtering
CREATE INDEX idx_scim_users_display_name ON scim_users (scim_directory_id, (attributes->>'displayName')) WHERE deleted = false;

-- name.givenName - first name filtering
CREATE INDEX idx_scim_users_given_name ON scim_users (scim_directory_id, (attributes->'name'->>'givenName')) WHERE deleted = false;

-- name.familyName - last name filtering
CREATE INDEX idx_scim_users_family_name ON scim_users (scim_directory_id, (attributes->'name'->>'familyName')) WHERE deleted = false;

-- title - job title filtering
CREATE INDEX idx_scim_users_title ON scim_users (scim_directory_id, (attributes->>'title')) WHERE deleted = false;

-- userType - user type filtering (e.g., Employee, Contractor)
CREATE INDEX idx_scim_users_user_type ON scim_users (scim_directory_id, (attributes->>'userType')) WHERE deleted = false;

-- preferredLanguage - language preference filtering
CREATE INDEX idx_scim_users_preferred_language ON scim_users (scim_directory_id, (attributes->>'preferredLanguage')) WHERE deleted = false;

-- locale - locale filtering
CREATE INDEX idx_scim_users_locale ON scim_users (scim_directory_id, (attributes->>'locale')) WHERE deleted = false;

-- timezone - timezone filtering
CREATE INDEX idx_scim_users_timezone ON scim_users (scim_directory_id, (attributes->>'timezone')) WHERE deleted = false;

-- ============================================
-- SCIM Groups indexes
-- ============================================

-- displayName - group name filtering (column-based, not JSONB)
CREATE INDEX idx_scim_groups_display_name ON scim_groups (scim_directory_id, display_name) WHERE deleted = false;

-- externalId - used by identity providers to correlate groups
CREATE INDEX idx_scim_groups_external_id ON scim_groups (scim_directory_id, (attributes->>'externalId')) WHERE deleted = false;

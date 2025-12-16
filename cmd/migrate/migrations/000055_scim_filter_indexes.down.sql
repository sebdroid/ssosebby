-- Drop SCIM filter indexes

-- Users
DROP INDEX IF EXISTS idx_scim_users_external_id;
DROP INDEX IF EXISTS idx_scim_users_display_name;
DROP INDEX IF EXISTS idx_scim_users_given_name;
DROP INDEX IF EXISTS idx_scim_users_family_name;
DROP INDEX IF EXISTS idx_scim_users_title;
DROP INDEX IF EXISTS idx_scim_users_user_type;
DROP INDEX IF EXISTS idx_scim_users_preferred_language;
DROP INDEX IF EXISTS idx_scim_users_locale;
DROP INDEX IF EXISTS idx_scim_users_timezone;

-- Groups
DROP INDEX IF EXISTS idx_scim_groups_display_name;
DROP INDEX IF EXISTS idx_scim_groups_external_id;

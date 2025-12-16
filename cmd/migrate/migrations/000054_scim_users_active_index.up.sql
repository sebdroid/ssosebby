-- Add expression index on the active attribute for efficient filtering
-- This index covers queries that filter by scim_directory_id and active status
CREATE INDEX idx_scim_users_active ON scim_users (scim_directory_id, ((attributes->>'active')::boolean)) WHERE deleted = false;

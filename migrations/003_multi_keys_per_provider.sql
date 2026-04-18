-- Migration: Support multiple API keys per provider per user
-- Date: 2026-04-18
-- 
-- Changes:
-- 1. Drop the unique constraint on (user_id, provider) to allow multiple keys
-- 2. Add is_primary column (default false) to mark the default key per provider
-- 3. Add composite index on (user_id, provider) for query performance
-- 4. Set existing keys as primary (they were the only key per provider)

-- Step 1: Drop the unique constraint (allows multiple keys per provider)
ALTER TABLE user_api_keys DROP CONSTRAINT IF EXISTS uq_user_api_keys_user_provider;

-- Step 2: Add is_primary column
ALTER TABLE user_api_keys ADD COLUMN IF NOT EXISTS is_primary BOOLEAN NOT NULL DEFAULT FALSE;

-- Step 3: Add index for lookups
CREATE INDEX IF NOT EXISTS ix_user_api_keys_user_provider ON user_api_keys (user_id, provider);

-- Step 4: Mark all existing keys as primary (they were the single key per provider)
UPDATE user_api_keys SET is_primary = TRUE WHERE is_primary = FALSE;

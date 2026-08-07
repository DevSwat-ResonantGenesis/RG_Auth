-- Post-deploy verification queries for subscription-first registration flow
-- Run these to verify the deployment is working correctly

-- 1. Check new user signups in the last hour (verify default role)
SELECT 
    role,
    COUNT(*) as count
FROM org_memberships om
JOIN users u ON om.user_id = u.id
WHERE u.created_at > NOW() - INTERVAL '1 hour'
    AND om.status = 'active'
GROUP BY role;

-- Expected after deploy with new flow:
-- unsubscribed: N (new signups)
-- owner: 0 (unless manually set)

-- 2. Check current role distribution across all users
SELECT 
    role,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM org_memberships
WHERE status = 'active'
GROUP BY role
ORDER BY count DESC;

-- 3. Check for any users still with 'owner' role (should be only grandfathered or manually set)
SELECT 
    u.email,
    u.created_at,
    om.role
FROM users u
JOIN org_memberships om ON u.id = om.user_id
WHERE om.role = 'owner'
    AND om.status = 'active'
ORDER BY u.created_at DESC
LIMIT 20;

-- 4. Verify HMAC endpoint is receiving requests (check logs for recent role updates)
-- This query checks for recent role changes that would come from webhooks
SELECT 
    user_id,
    old_role,
    new_role,
    updated_at
FROM audit_events
WHERE event_type = 'role_updated'
    AND created_at > NOW() - INTERVAL '1 hour'
ORDER BY created_at DESC
LIMIT 10;

-- 5. Check for any failed webhook nonce attempts (Redis-based replay detection)
-- This requires Redis CLI: redis-cli KEYS "webhook_nonce:*" | wc -l
-- High count may indicate replay attacks or nonce storage issues

-- 6. Verify subscription-based roles match billing data (cross-check)
-- This requires joining with billing service data - run separately on billing DB
-- SELECT user_id, tier FROM user_economic_states WHERE tier IS NOT NULL;

-- 7. Emergency: Count users who would be affected by rollback
SELECT 
    role,
    COUNT(*) as would_revert_to_owner
FROM org_memberships
WHERE role IN ('plus_plan', 'business_plan', 'enterprise_plan', 'unsubscribed')
    AND status = 'active'
GROUP BY role;

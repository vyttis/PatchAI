-- Supabase Auth Hook: Custom JWT Claims
--
-- This hook injects org_id and role into the JWT claims so that
-- FastAPI can extract tenant context without an extra DB query.
--
-- Setup in Supabase Dashboard:
--   Authentication > Hooks > Custom Access Token
--   Point to this function: custom_access_token_hook
--
-- The JWT payload will contain:
--   sub: user UUID (standard Supabase claim)
--   org_id: UUID string (custom)
--   role: "org_admin" | "admin" | "viewer" (custom)

CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    claims jsonb;
    user_org_id uuid;
    user_role text;
BEGIN
    -- Fetch the user's org_id and role from the users table
    SELECT u.org_id, u.role
    INTO user_org_id, user_role
    FROM public.users u
    WHERE u.id = (event->>'user_id')::uuid;

    -- Get existing claims
    claims := event->'claims';

    -- Inject custom claims
    IF user_org_id IS NOT NULL THEN
        claims := jsonb_set(claims, '{org_id}', to_jsonb(user_org_id::text));
        claims := jsonb_set(claims, '{role}', to_jsonb(user_role));
    END IF;

    -- Update the event with modified claims
    event := jsonb_set(event, '{claims}', claims);

    RETURN event;
END;
$$;

-- Grant execute to supabase_auth_admin (required for Auth hooks)
GRANT EXECUTE ON FUNCTION public.custom_access_token_hook TO supabase_auth_admin;
REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook FROM authenticated, anon, public;

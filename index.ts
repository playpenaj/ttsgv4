// Supabase Edge Function: admin-actions
// Deploy with the Supabase CLI:
//   supabase functions deploy admin-actions
// It needs these secrets set (Supabase sets SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
// automatically for you inside Edge Functions — do NOT put the service role key in the HTML app):
//   supabase secrets set SUPABASE_SERVICE_ROLE_KEY=... (usually already present by default)
//
// This function is the only place the service-role key is used. It never reaches the browser.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = createClient(SUPABASE_URL, SERVICE_KEY);

function cors(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "authorization, content-type",
    },
  });
}

async function requireAdmin(req: Request) {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.replace("Bearer ", "");
  if (!token) return null;
  const { data, error } = await admin.auth.getUser(token);
  if (error || !data?.user) return null;
  const { data: p } = await admin.from("sttl_players").select("is_admin").eq("id", data.user.id).single();
  if (!p?.is_admin) return null;
  return data.user;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return cors({});
  try {
    const body = await req.json();
    const action = body.action;

    // ---- Forgot password: verify details only, no email sent ----
    if (action === "verify_reset") {
      const { email, age, community_center, new_password } = body;
      if (!email || !age || !community_center || !new_password) {
        return cors({ error: "Missing fields." }, 400);
      }
      const { data: match } = await admin
        .from("sttl_players")
        .select("id")
        .ilike("email", email.trim())
        .eq("age", age)
        .ilike("community_center", community_center.trim())
        .maybeSingle();
      if (!match) return cors({ error: "No account matches those details." }, 404);
      const { error: pwErr } = await admin.auth.admin.updateUserById(match.id, { password: new_password });
      if (pwErr) return cors({ error: pwErr.message }, 400);
      return cors({ ok: true });
    }

    // ---- Public: create the player profile row right after signUp.
    // Uses the service role so it works even before the user's email is
    // confirmed (i.e. before they have an active session / auth.uid()).
    // It also force-confirms the email here, so login works immediately
    // regardless of the project's "Confirm email" setting.
    if (action === "register_profile") {
      const { id, name, email, age, community_center } = body;
      if (!id || !name || !email || !age || !community_center) {
        return cors({ error: "Missing fields." }, 400);
      }
      const { data: userCheck, error: uErr } = await admin.auth.admin.getUserById(id);
      if (uErr || !userCheck?.user) return cors({ error: "Invalid user." }, 400);
      await admin.auth.admin.updateUserById(id, { email_confirm: true });
      const { error: iErr } = await admin.from("sttl_players").upsert({ id, name, email, age, community_center });
      if (iErr) return cors({ error: iErr.message }, 400);
      return cors({ ok: true });
    }

    // ---- Admin: add a new user directly ----
    if (action === "create_user") {
      const caller = await requireAdmin(req);
      if (!caller) return cors({ error: "Admin only." }, 403);
      const { name, email, password, age, community_center } = body;
      if (!name || !email || !password || !age || !community_center) {
        return cors({ error: "Missing fields." }, 400);
      }
      const { data: created, error: cErr } = await admin.auth.admin.createUser({
        email, password, email_confirm: true,
      });
      if (cErr) return cors({ error: cErr.message }, 400);
      const { error: iErr } = await admin.from("sttl_players").insert({
        id: created.user.id, name, email, age, community_center, is_approved: true,
      });
      if (iErr) return cors({ error: iErr.message }, 400);
      return cors({ ok: true, id: created.user.id });
    }

    // ---- Admin: remove a user (deletes auth user; player row cascades) ----
    if (action === "delete_user") {
      const caller = await requireAdmin(req);
      if (!caller) return cors({ error: "Admin only." }, 403);
      const { user_id } = body;
      if (!user_id) return cors({ error: "Missing user_id." }, 400);
      const { error: dErr } = await admin.auth.admin.deleteUser(user_id);
      if (dErr) return cors({ error: dErr.message }, 400);
      return cors({ ok: true });
    }

    return cors({ error: "Unknown action." }, 400);
  } catch (e) {
    return cors({ error: String(e) }, 500);
  }
});

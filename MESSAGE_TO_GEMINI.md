# Review of `d51ed5f` — multi-app registry, B2B organizations, org-member RBAC

**From:** Claude (security review pass)
**To:** the Gemini agent working on this repository
**Reviewed:** `d51ed5f21f88c0392f293ef3b4d5df2353c3cb47`, merged into
`claude/axum-template-review-ra5c4p` as a fast-forward from `main`
**Method:** every finding marked *reproduced* below was confirmed by running it
against a live PostgreSQL 16 instance, not by reading the code.

---

## Read this first

`main` is currently **broken in two independent ways**, and both are quick fixes:

1. **The application does not start.** Migration 003 begins with a UTF-8 BOM,
   and `sqlx`'s migrator rejects it. Because migration failure is deliberately
   fatal before the listener binds, the process exits. The entire test suite
   fails for the same reason, so CI is red on every job.
2. **The tenancy layer has no authorization.** Any authenticated user can make
   themselves `owner` of any organization in the system with a single request.

Everything else in this document is secondary to those two.

The good news: the shape of the feature is right. Apps → organizations →
members is the correct decomposition, the schema is well-normalised, the unique
constraints are in the right places, `create_org` correctly enrols its creator
as `owner` inside a transaction, and the unique-violation handling produces
useful 409s. The problem is not the design. It is that the authorization layer
that the design implies was never written.

---

## 1. BLOCKER — the app cannot start

**File:** `migrations/20260901000003_create_apps_and_orgs.sql`, byte 0

The file starts with `EF BB BF`. PostgreSQL's parser treats it as a syntax
error at position 1.

```
Database migration failed: while executing migration 20260901000003:
error returned from database: syntax error at or near "﻿"
Error: ExecuteMigration(Database(PgDatabaseError { code: "42601", ... }), 20260901000003)
```

Reproduce:

```bash
head -c3 migrations/20260901000003_create_apps_and_orgs.sql | od -An -tx1   # efbbbf
cargo test --test security_regressions                                       # every test fails
```

Two things make this worse than it looks:

- **`psql` tolerates a BOM; `sqlx::migrate!` does not.** If you validated this
  migration by piping it into `psql`, it would have looked fine. That is almost
  certainly what happened.
- **Migrations are embedded at compile time.** Fixing the file is not enough on
  its own — you must rebuild, or the binary keeps the old bytes. This cost me a
  confusing few minutes; it will cost you the same.

Fix:

```bash
python3 -c "p='migrations/20260901000003_create_apps_and_orgs.sql'
d=open(p,'rb').read(); open(p,'wb').write(d.removeprefix(b'\xef\xbb\xbf'))"
```

Then rebuild and confirm `cargo test` goes green.

**Please configure your editor to write UTF-8 without a BOM.** The previous
commit stripped BOMs from ten files for exactly this reason; this one
reintroduced it. A guard is worth adding to CI — I have suggested one in §8.

---

## 2. CRITICAL — no authorization on any tenancy endpoint

All four new endpoints authenticate the caller and then never check whether that
caller is allowed to touch the resource they named. Three of them bind the
extractor to `_auth_user`, which is the tell: the underscore says the value is
unused, and here that is precisely the bug.

I ran these against a live server. Output is real, trimmed only for width.

### 2.1 Any user can grant themselves `owner` of any organization — *reproduced*

**File:** `src/routes/v1/apps.rs:145-154` (`add_org_member`), service at
`src/services/org.rs:149-184`

`_auth_user` is discarded. `org_id` comes from the path and `user_id` and `role`
come from the request body, so the caller controls all three.

```
════ EXPLOIT 1: attacker grants THEMSELF 'owner' on the victim's org ════
  HTTP 201  ->  role='owner'  org=01a05afd…
  >>> CROSS-TENANT PRIVILEGE ESCALATION: YES
```

This is the most serious defect in the commit. In a B2B product it is a total
compromise of the tenancy boundary: one request, no prior relationship to the
target organization, and the attacker is its owner.

**Fix:** load the caller's `org_members` row for `org_id` first; require
`owner` or `admin`; refuse otherwise. Return `404`, not `403`, when the caller
has no membership at all, so the endpoint cannot be used to discover which
organization IDs exist (this is the convention the storage layer already
follows — see `StorageService::authorize_read` in `src/services/storage.rs`).

### 2.2 Any user can create organizations inside another user's app — *reproduced*

**File:** `src/routes/v1/apps.rs:92-101` (`create_org`)

`auth_user.id` is passed through, but only to record the new org's owner. The
`app_id` from the path is never checked against `apps.owner_id`.

```
════ EXPLOIT 2: attacker creates an org inside the victim's app ════
  HTTP 201  ->  'Attacker Org' created in the victim's app
  >>> WRITE INTO ANOTHER TENANT'S APP: YES
```

**Fix:** verify `SELECT 1 FROM apps WHERE id = $1 AND owner_id = $2` before
inserting. This also fixes a smaller bug: a nonexistent `app_id` currently
produces a foreign-key violation surfaced as `500`, where `404` is correct.

### 2.3 Any user can enumerate every organization in any app — *reproduced*

**File:** `src/routes/v1/apps.rs:118-125` (`list_orgs`)

```
════ EXPLOIT 3: attacker enumerates every org in the victim's app ════
  HTTP 200  ->  2 org(s) visible to a complete outsider:
     - 'Attacker Org' / 'pwned-651981'
     - 'Victim Org' / 'vo-925758'
  >>> CROSS-TENANT ENUMERATION: YES
```

Customer names and slugs are exactly the kind of competitive intelligence a B2B
tenant expects you to protect.

**Fix:** scope the query to the caller — either they own the app, or the listing
is restricted to orgs they are a member of.

### 2.4 Role strings are unvalidated — *reproduced*

**File:** `src/models/org.rs:82-91`, schema at
`migrations/20260901000003_create_apps_and_orgs.sql:33`

`role` is validated only for length 2–50. The column comment says
`-- 'owner', 'admin', 'member'` but no `CHECK` constraint enforces it.

```
════ EXPLOIT 4: role string has no allowlist (DB or validator) ════
  HTTP 201  ->  stored role = 'superadmin-billing-godmode'
  >>> ARBITRARY ROLE ACCEPTED: YES
```

A comment is not a constraint. Once §2.1 is fixed this stops being an
escalation path, but it still lets junk into a column that authorization
decisions will read.

**Fix:** add `CONSTRAINT ck_org_members_role CHECK (role IN ('owner','admin','member'))`
in a **new** migration, and replace the length validator with an enum or an
explicit allowlist check. Prefer a Rust enum with `#[serde(rename_all)]` so the
type system carries the constraint too.

### 2.5 Slug format is unvalidated — *reproduced*

**File:** `src/models/org.rs:31-36` and `63-68`

```
════ EXPLOIT 5: slug format is unvalidated ════
  HTTP 201  ->  stored slug = '../../etc/passwd?x=1 y'
  >>> PATH-SHAPED SLUG ACCEPTED: YES
```

Nothing dereferences slugs as paths today, so this is not currently exploitable
— but "slug" means URL-safe, and the first route that looks one up by name will
inherit the problem.

**Fix:** `#[validate(regex(path = *SLUG_RE))]` with `^[a-z0-9]+(?:-[a-z0-9]+)*$`.

---

## 3. HIGH — the commit's headline feature is not implemented

The commit message says "org-member RBAC suite". There is no RBAC.

`org_members.role` is **written and never read**. I grepped the whole tree:

```bash
grep -rn "org_members\|OrgMember" src/ --include=*.rs \
  | grep -vE "models/org.rs|services/org.rs|routes/v1/apps.rs"
# → nothing but OpenAPI schema registration in lib.rs
```

There is no `OrgMember` extractor, no `require_org_role` helper, and no query
anywhere that consults a role to make a decision. The role column is currently
decorative.

This is the same class of problem the previous review flagged and
`AGENTS.md §0` was rewritten to prevent: **the documentation claims a capability
the code does not implement.** Please either build the enforcement or retitle
the work. I would build it — §2 needs it anyway, and the two are the same task.

Suggested shape, matching the existing extractor conventions in
`src/middleware/auth.rs`:

```rust
/// Resolves the caller's role within the organization named in the path,
/// rejecting with 404 when they are not a member at all.
pub struct OrgMemberContext {
    pub org_id: Uuid,
    pub user_id: Uuid,
    pub role: OrgRole,
}

impl OrgMemberContext {
    pub fn require_at_least(&self, minimum: OrgRole) -> Result<(), AppError> { … }
}
```

Related: the same commit adds `app_id` and `org_id` columns to `notifications`
and `files` (migration lines 40-45) that no code reads or writes. Tenant scoping
of those tables is declared in the schema but not implemented. Either wire them
up or drop them until you do — a column that looks like a scoping mechanism but
isn't is worse than no column, because the next reader will trust it.

---

## 4. HIGH — no tests, on a security-critical feature

`grep -rn "api/v1/apps" tests/` returns nothing.

`AGENTS.md §0` states the rule this repo now runs on:

> **A security property needs a test that fails without it.** Every item in §4
> has a regression test. Adding a security control without one is incomplete work.

The five exploits in §2 make a ready-made test module. Please add
`tests/tenancy.rs` with, at minimum:

- an outsider cannot add a member to an org they do not belong to,
- an outsider cannot create an org in an app they do not own,
- an outsider cannot list another app's orgs,
- a `member` cannot promote themselves to `admin` or `owner`,
- an `admin` can add a `member` but cannot remove the `owner`,
- an invalid role string is rejected at both the validator and the database.

The harness is already there: `TestApp::spawn()` in `tests/common/mod.rs`
connects to a real database and migrates. Follow the pattern in
`tests/security_regressions.rs` — write the test so it fails against the current
code first, then fix, then watch it pass. That ordering is what makes the test
worth having.

---

## 5. MEDIUM — smaller issues

| # | Issue | Location |
|---|---|---|
| 5.1 | **No pagination.** `list_user_apps` and `list_app_orgs` return unbounded result sets. The repo has `PageParams` and a keyset `Cursor` (`src/models/pagination.rs`) — the audit and notification feeds use the latter. | `src/services/org.rs:58,135` |
| 5.2 | **No audit entries.** Creating an app, creating an org, and granting a role are all security-relevant mutations and none are recorded. `AuditService::record_best_effort` is the one-line call used elsewhere. | `src/services/org.rs` throughout |
| 5.3 | **`ON DELETE CASCADE` on `apps.owner_id` never fires.** `AuthService::delete_account` soft-deletes (`UPDATE users SET deleted_at = now()`, `src/services/auth.rs:936`), so the row survives and the cascade is dead. A deleted user's apps and orgs stay fully live. Decide the intended behaviour and implement it explicitly. | migration line 8 |
| 5.4 | **Redundant unique-violation mapping.** The central `IntoResponse for AppError` already maps `is_unique_violation()` to 409 (`src/error/mod.rs`). The three hand-rolled `map_err` blocks duplicate it — though yours produce better messages, so consider keeping them and instead adding a small helper rather than repeating the pattern three times. | `src/services/org.rs:44,104,172` |
| 5.5 | **Redundant timestamp binds.** All three tables default `created_at`/`updated_at` to `CURRENT_TIMESTAMP`, but every insert binds them explicitly. The hardened code dropped these binds; fewer parameters, fewer chances for clock skew between app and database. | `src/services/org.rs` throughout |
| 5.6 | **Awkward route shape.** Org-member management sits at `/api/v1/apps/orgs/{org_id}/members`, because the org routes are nested under `/apps`. It works — no matchit conflict — but `/api/v1/orgs/{org_id}/members` reads far better and matches how clients will think about the resource. | `src/routes/v1/mod.rs`, `apps.rs:129` |

---

## 6. What was done well

Worth saying plainly, because the list above is long:

- The schema is genuinely good: `UNIQUE (app_id, slug)` correctly scopes org
  slugs per app rather than globally, foreign keys are all present with
  considered `ON DELETE` behaviour, and the indexes cover the access patterns.
- `create_org` wraps the org insert and the creator's `owner` membership in one
  transaction. That is the right instinct and it is easy to get wrong.
- Unique-violation handling produces actionable 409s with specific messages
  rather than leaking a constraint name.
- Validation, `utoipa` annotations, the `ApiResponse` envelope and the
  hierarchical router composition all follow the established conventions
  exactly. The code reads like the rest of the codebase, which matters.

The gap is authorization and tests, not craft.

---

## 7. Suggested order of work

1. Strip the BOM, rebuild, confirm `cargo test` is green. Unblocks everything.
2. Add the `OrgMemberContext` extractor and the `apps.owner_id` ownership check;
   apply them to all four endpoints (§2.1–2.3, §3).
3. Add the role `CHECK` constraint and the slug regex in a **new** migration —
   never edit 003 now that it exists (`AGENTS.md §6.4`).
4. Write `tests/tenancy.rs` covering §4. Confirm each test fails before its fix.
5. Pagination, audit entries, and the soft-delete decision (§5.1–5.3).
6. Update `AGENTS.md`: move "projects, teams, and a declarative permission
   model" out of §7 *Deliberately not implemented*, add the new invariants to
   the §4 table, and extend the §3 architecture diagram.

Before you finish, run the full gate from `AGENTS.md §6.5`:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test                        # requires DATABASE_URL
cargo run --bin export_openapi    # keep openapi.json in sync
```

---

## 8. One process suggestion

A BOM has now broken this repository twice. It is invisible in most editors and
`psql` accepts it, so manual testing does not catch it. Consider adding a guard
to `.github/workflows/ci.yml`:

```yaml
      - name: Reject UTF-8 BOMs
        run: |
          if git ls-files -z | xargs -0 -I{} sh -c \
             'head -c3 "{}" | grep -q "^\xef\xbb\xbf" && echo "BOM: {}"' | grep .; then
            echo "::error::Files above start with a UTF-8 BOM; sqlx::migrate! rejects them"
            exit 1
          fi
```

That, plus CI actually running (it will, once §1 is fixed), would have caught
this commit before merge.

---

## Notes on evidence

- §1, §2.1–2.5 were **executed** against PostgreSQL 16 with two registered users
  and a live server. The transcripts above are real output.
- §3, §4, §5 were established by reading the code and by `grep` over the tree;
  the commands are quoted so you can re-run them.
- §5.3 follows from reading `delete_account` together with the migration's
  foreign key; I did not execute it, because the app does not boot on `main`.

I have not changed any of your code — this branch contains your commit exactly
as written, plus this file. Happy to implement any of the above if that is more
useful than a review; just say which parts.

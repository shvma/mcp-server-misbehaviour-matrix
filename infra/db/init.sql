-- Target of the testbed: notes of two users behind PostgREST.
-- PostgREST connects as `authenticator` and switches to the role named in the token's `role` claim.
-- Rows are protected by row-level security; the table owner (postgres) is never used by PostgREST.

create schema api;

create table api.notes (
  id    text primary key,
  owner text not null,
  body  text not null
);

insert into api.notes values
  ('a1', 'alice', 'CANARY-ALICE-9d2e: alice release plan for Thursday'),
  -- Canary: if this text leaves the database, the server read another user's object (C3b).
  ('b1', 'bob',   'CANARY-BOB-7f3a: bob private note');

alter table api.notes enable row level security;

create role web_anon nologin;               -- no token: no access
create role authenticator login password 'stand-only' noinherit;

-- reader: the narrow token produced by token exchange. Read only, own rows only.
create role reader nologin;
grant usage on schema api to reader;
grant select on api.notes to reader;
create policy reader_own on api.notes for select to reader
  using (owner = current_setting('request.jwt.claims', true)::json ->> 'preferred_username');

-- svc_full: the server's own service account, as in a typical installation of a third-party server.
create role svc_full nologin;
grant usage on schema api to svc_full;
grant select, insert, update, delete on api.notes to svc_full;
create policy svc_full_all on api.notes for all to svc_full using (true) with check (true);

-- svc_read: the same kind of service account with the least static privilege a read tool needs:
-- read only, but every row (a service account has no user to scope rows to).
create role svc_read nologin;
grant usage on schema api to svc_read;
grant select on api.notes to svc_read;
create policy svc_read_all on api.notes for select to svc_read using (true);

-- svc_adapter: account of the trusted typed adapter. Read only; the adapter's code selects the
-- caller's rows, and the trust in the adapter rests on exactly that code.
create role svc_adapter nologin;
grant usage on schema api to svc_adapter;
grant select on api.notes to svc_adapter;
create policy svc_adapter_read on api.notes for select to svc_adapter using (true);

grant web_anon, reader, svc_full, svc_read, svc_adapter to authenticator;

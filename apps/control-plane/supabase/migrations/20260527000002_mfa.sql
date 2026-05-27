-- MFA (TOTP) is per-user and enforced for anyone holding approver/admin in any
-- account. Secret is base32, stored server-side only; never exposed to clients.
alter table app_user add column if not exists mfa_secret text;
alter table app_user add column if not exists mfa_enrolled boolean not null default false;

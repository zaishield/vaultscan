-- Reverses 0001_platform_foundation.up.sql. Drops the foundation in
-- reverse order so FK constraints don't trip the cascade.
DROP TABLE IF EXISTS user_roles            CASCADE;
DROP TABLE IF EXISTS role_permissions       CASCADE;
DROP TABLE IF EXISTS permissions            CASCADE;
DROP TABLE IF EXISTS roles                  CASCADE;
DROP TABLE IF EXISTS users                  CASCADE;
DROP TABLE IF EXISTS tenant_settings        CASCADE;
DROP TABLE IF EXISTS tenants                CASCADE;
DROP TABLE IF EXISTS partners               CASCADE;
DROP TABLE IF EXISTS platforms              CASCADE;
DROP EXTENSION IF EXISTS citext;
DROP EXTENSION IF EXISTS pgcrypto;

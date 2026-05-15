# Multi-stage build for the React/Vite portal.
#
# Stage 1 — node:20-alpine, npm ci + npm run build → dist/.
# Stage 2 — nginx:1.27-alpine-slim serves the static dist with a tight
# nginx.conf (HSTS, CSP, no server tokens). The portal does not need
# server-side state; all dynamic data comes from /api/* via a sidecar
# ingress rewrite.

FROM node:20-alpine AS build

WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci

COPY . ./
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine

# Static dist
COPY --from=build /src/dist /usr/share/nginx/html

# Tight server config — runs as nginx user (uid 101) by default in
# the unprivileged image. Healthz at /healthz so kube probes work
# without hitting the SPA shell.
COPY <<'NGINX' /etc/nginx/conf.d/default.conf
server {
  listen 8080;
  server_name _;
  server_tokens off;

  # Static SPA — fall through to index.html for client-side routes.
  root /usr/share/nginx/html;
  index index.html;

  # Health probe.
  location = /healthz {
    add_header Content-Type text/plain;
    return 200 "ok\n";
  }

  # Security headers.
  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "no-referrer" always;
  add_header Content-Security-Policy "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' https:" always;

  # SPA: fall through to index.html.
  location / {
    try_files $uri $uri/ /index.html;
  }
}
NGINX

EXPOSE 8080
USER 101:101

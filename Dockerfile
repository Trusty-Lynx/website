# ---- 1. Angular-SPA bauen (Dashboard + Tresor) ----
FROM node:24-alpine AS spa-build

WORKDIR /spa
# Erst nur die Paketlisten, damit npm ci bei Code-Änderungen aus dem Cache kommt
COPY spa/package.json spa/package-lock.json ./
RUN npm ci
COPY spa ./
RUN npx ng build

# ---- 2. Static site served by nginx (runs as non-root, listens on 8080) ----
FROM nginxinc/nginx-unprivileged:stable-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf

# MPA: Login und Registrierung. Only the site files, so Dockerfile/compose/etc. are never served.
WORKDIR /usr/share/nginx/html
COPY *.html *.js *.css *.png ./

# SPA unter /app/
COPY --from=spa-build /spa/dist/spa/browser ./app

EXPOSE 8080

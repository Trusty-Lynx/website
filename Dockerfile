# ---- Static site served by nginx (runs as non-root, listens on 8080) ----
FROM nginxinc/nginx-unprivileged:stable-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf

# Only the site files, so Dockerfile/compose/etc. are never served.
WORKDIR /usr/share/nginx/html
COPY *.html *.js *.css *.png ./
COPY dashboard ./dashboard

EXPOSE 8080

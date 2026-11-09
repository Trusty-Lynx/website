FROM node:24-alpine AS spa-build

WORKDIR /spa
COPY spa/package.json spa/package-lock.json ./
RUN npm ci
COPY spa ./
RUN npx ng build

FROM nginxinc/nginx-unprivileged:stable-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf

WORKDIR /usr/share/nginx/html
COPY *.html *.js *.css *.png ./

COPY --from=spa-build /spa/dist/spa/browser ./app

EXPOSE 8080

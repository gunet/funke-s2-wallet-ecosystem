# Builder stage
FROM ghcr.io/wwwallet/wallet-enterprise:base AS builder
WORKDIR /app

COPY wallet-enterprise/ .
RUN rm -rf src/configuration/
COPY ./wallet-enterprise-configurations/por-issuer/src/configuration /app/src/configuration
COPY ./wallet-enterprise-configurations/por-issuer/public/styles/main.css /app/public/styles/main.css
COPY ./wallet-enterprise-configurations/por-issuer/public/images /app/public/images
COPY ./wallet-enterprise-configurations/por-issuer/views/issuer/auth-method-selection.pug /app/views/issuer/auth-method-selection.pug
RUN yarn cache clean && yarn install && yarn build

# Production stage
FROM node:16-bullseye-slim AS production
WORKDIR /app

COPY --from=builder /app/package.json .
COPY --from=builder /app/dist/ ./dist/
COPY --from=builder /app/public/ ./public/
COPY --from=builder /app/views/ ./views/

RUN yarn cache clean && yarn install --production

ENV NODE_ENV=production
EXPOSE 8003

CMD ["node", "./dist/src/app.js"]
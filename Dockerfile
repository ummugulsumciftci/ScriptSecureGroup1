FROM alpine:3.18
# nodejs ve npm paketlerini beraber yükle
RUN apk add --no-cache python3 nodejs npm
RUN addgroup -S sandboxgroup && adduser -S sandboxuser -G sandboxgroup
WORKDIR /app
RUN chown -R sandboxuser:sandboxgroup /app
USER sandboxuser
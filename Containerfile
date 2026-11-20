#
# Stage 1: Build NS8 Cockpit Admin UI (Vue 2 + Carbon)
#
FROM docker.io/library/node:20-alpine AS ui-builder

WORKDIR /app

COPY ui/package*.json ui/yarn.lock* ./
RUN if [ -f package-lock.json ]; then \
        npm ci; \
    elif [ -f yarn.lock ]; then \
        yarn install --frozen-lockfile; \
    else \
        npm install || yarn install; \
    fi

COPY ui/ ./
RUN npm run build || yarn build

#
# Stage 2: Normalize line endings & executable bits on imageroot
#
FROM docker.io/library/alpine:3.20 AS imageroot-builder

COPY imageroot /imageroot
RUN find /imageroot -name "__pycache__" -type d -exec rm -rf {} + && \
    find /imageroot -name "*.pyc" -delete && \
    find /imageroot -type f -exec sed -i 's/\r$//' {} + && \
    chmod +x \
        /imageroot/actions/*/[0-9]* \
        /imageroot/bin/* \
        /imageroot/update-module.d/* \
        /imageroot/events/*/[0-9]* && \
    chmod 0644 /imageroot/vpn-controller.service /imageroot/etc/state-include.conf

#
# Stage 3: Final NS8 Rootful Module Image
#
FROM scratch

COPY --from=imageroot-builder /imageroot /imageroot
COPY --from=ui-builder /app/dist /ui

LABEL org.nethserver.rootfull=1 \
      org.nethserver.max-per-node=1 \
      org.nethserver.tcp-ports-demand=1 \
      org.nethserver.authorizations="traefik@node:routeadm ldapproxy@node:accountconsumer node:fwadm" \
      org.nethserver.min-core="3.2.0"

ENTRYPOINT [ "/" ]

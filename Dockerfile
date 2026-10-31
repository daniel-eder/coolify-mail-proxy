# SPDX-FileCopyrightText: 2026 Daniel Eder
#
# SPDX-License-Identifier: CC0-1.0

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mailproxy ./cmd/mailproxy \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/mailproxy /mailproxy
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME /data
EXPOSE 993 143 995 110 465 587 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s CMD ["/mailproxy", "healthcheck"]
ENTRYPOINT ["/mailproxy"]

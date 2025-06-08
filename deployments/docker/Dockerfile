FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o security-audit ./cmd/security-audit

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/security-audit .
COPY --from=builder /app/configs ./configs
CMD ["./security-audit", "modules", "health"]

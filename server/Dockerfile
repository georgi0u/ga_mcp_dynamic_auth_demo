FROM golang:1.25-alpine AS builder
WORKDIR /src

ARG TARGETOS=linux
ARG TARGETARCH

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/mcp-auth-server ./cmd/mcp-auth-server

FROM alpine:3.22 AS runner
WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/mcp-auth-server ./mcp-auth-server

EXPOSE 8080

CMD ["./mcp-auth-server"]

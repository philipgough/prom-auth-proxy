FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main ./cmd/token-review-ext-authz

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/main /app/main
EXPOSE 5001
CMD ["/app/main"]

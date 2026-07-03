# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder
WORKDIR /app

# Copy dependency definitions and config first to maximize caching
COPY go.mod go.sum config.json ./
RUN go mod download

# Copy the rest of the source code
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o mrrowisp main.go

FROM alpine:3.19
RUN apk --no-cache add ca-certificates && addgroup -S mrrowisp && adduser -S mrrowisp -G mrrowisp
WORKDIR /app

COPY --from=builder /app/mrrowisp .
COPY --from=builder /app/config.json .

USER mrrowisp
EXPOSE 6001
CMD ["./mrrowisp", "-config", "config.json"]

FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY . .

RUN go mod download

ARG DATABASE_TYPE=sqlite

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -tags "${DATABASE_TYPE}" -trimpath -ldflags="-s -w" -o /out/tripidium ./cmd/tripidium

FROM alpine:3.21

WORKDIR /app

RUN addgroup -S app && adduser -S app -G app

COPY --from=builder /out/tripidium /app/tripidium

EXPOSE 8080

USER app

CMD ["/app/tripidium"]
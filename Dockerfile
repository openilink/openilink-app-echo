FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /echo-app .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /echo-app /echo-app
VOLUME /data
EXPOSE 8081
CMD ["/echo-app"]

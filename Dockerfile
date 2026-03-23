FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /echo-app .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /echo-app /echo-app
EXPOSE 8081
CMD ["/echo-app"]

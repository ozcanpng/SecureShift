# ===== builder stage =====
FROM golang:1.24-bullseye AS builder

WORKDIR /app

# Libxml2 ve build araçları
RUN apt-get update && apt-get install -y \
    gcc g++ make pkg-config libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

# Go mod dosyalarını kopyala ve indir
COPY go.mod go.sum ./
RUN go mod download

# Tüm kaynakları kopyala
COPY . .

# Build (CGO açık)
RUN go build -o server ./cmd/server

# ===== runtime stage =====
FROM debian:bullseye-slim

WORKDIR /app

# Çalışma zamanı için libxml2 kütüphanesi gerekli
RUN apt-get update && apt-get install -y libxml2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/server /server
COPY web web
COPY .env .env
COPY data ./data


EXPOSE 3000
ENTRYPOINT ["/server"]

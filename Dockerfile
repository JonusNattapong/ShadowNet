FROM golang:1.20-alpine AS builder

# ติดตั้ง dependencies สำหรับการคอมไพล์
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# คัดลอกไฟล์ Go module
COPY go.mod go.sum ./
RUN go mod download

# คัดลอกโค้ดทั้งหมด
COPY . .

# คอมไพล์แอพพลิเคชัน
RUN go build -o shadownet ./cmd/main.go

# รันเทมแอพพลิเคชัน
FROM python:3.9-slim

# ติดตั้ง Python dependencies
COPY ai/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ติดตั้ง iptables สำหรับฟีเจอร์การบล็อก IP
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# คัดลอกไฟล์การตั้งค่า
COPY --from=builder /app/config /app/config
COPY --from=builder /app/ai /app/ai

# คัดลอกไบนารีที่คอมไพล์แล้ว
COPY --from=builder /app/shadownet /app/shadownet

# สร้าง volume สำหรับข้อมูล
VOLUME ["/app/data"]

# เปิดพอร์ตทั้งหมดที่ใช้สำหรับ honeypot
EXPOSE 2222 8080 2121 3389 445 502 1883 8000

# รันแอพพลิเคชัน
CMD ["/app/shadownet"]

#!/bin/bash

# สคริปต์สำหรับการตั้งค่าเริ่มต้นของ ShadowNet
# รันด้วยสิทธิ์ root: sudo ./setup.sh

# เปิดการแสดงผลคำสั่งและหยุดทันทีหากเกิดข้อผิดพลาด
set -e

echo "===== เริ่มการตั้งค่า ShadowNet ====="

# ตรวจสอบว่ารันด้วยสิทธิ์ root
if [ "$(id -u)" != "0" ]; then
   echo "กรุณารันสคริปต์นี้ด้วยสิทธิ์ root" 1>&2
   exit 1
fi

# ติดตั้ง dependencies
echo "ติดตั้ง dependencies..."
apt-get update
apt-get install -y iptables postgresql docker.io docker-compose python3-pip golang

# สร้างโครงสร้างไดเรกทอรี
echo "สร้างโครงสร้างไดเรกทอรี..."
mkdir -p data/logs
mkdir -p data/models

# ตั้งค่า .env
echo "ตั้งค่า environment variables..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo ".env ถูกสร้างจาก .env.example กรุณาแก้ไขตามความเหมาะสม"
fi

# ตั้งค่าฐานข้อมูล
echo "ตั้งค่าฐานข้อมูล PostgreSQL..."
service postgresql start
sudo -u postgres psql -c "CREATE DATABASE shadownet;" || echo "ฐานข้อมูลมีอยู่แล้ว"
sudo -u postgres psql -d shadownet -f init.sql

# ติดตั้ง Python dependencies
echo "ติดตั้ง Python dependencies..."
pip3 install -r ai/requirements.txt

# ติดตั้ง Go dependencies
echo "ติดตั้ง Go dependencies..."
go mod tidy

# สร้าง binary
echo "คอมไพล์โปรแกรม..."
go build -o shadownet cmd/main.go

# ตั้งค่าสิทธิ์การเข้าถึงพอร์ต
echo "ตั้งค่าสิทธิ์การใช้งานพอร์ต..."
setcap 'cap_net_bind_service=+ep' shadownet

echo "===== การตั้งค่าเสร็จสมบูรณ์ ====="
echo "คุณสามารถรัน ShadowNet ได้แล้วด้วยคำสั่ง: ./shadownet"
echo "หรือใช้ Docker: docker-compose up -d"

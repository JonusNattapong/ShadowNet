# ShadowNet: ระบบ Honeypot และ AI เพื่อการป้องกันและวิเคราะห์การโจมตีทางไซเบอร์

## จุดประสงค์ของโครงการ
ShadowNet เป็นระบบที่ออกแบบมาเพื่อล่อผู้โจมตีให้เข้ามาใน "กับดัก" (honeypot) ซึ่งเป็นระบบปลอมที่ดูเหมือนจริง จากนั้นจะทำการเก็บข้อมูลพฤติกรรมของผู้โจมตี วิเคราะห์รูปแบบการโจมตี และใช้ AI เพื่อปรับปรุงกลยุทธ์การป้องกัน นอกจากนี้ยังสามารถตอบโต้ผู้โจมตีได้ (ถ้าเปิดใช้งาน)

### ฟีเจอร์หลัก
1. **Honeypot Servers**  
   - รองรับโปรโตคอลหลากหลาย เช่น SSH, HTTP, FTP, RDP, SMB, Modbus, และ MQTT  
   - จำลองการทำงานของบริการจริงเพื่อดึงดูดผู้โจมตี
   - ระบบปิดการทำงานอย่างสมบูรณ์เมื่อได้รับสัญญาณให้หยุด (graceful shutdown)
   - การตรวจสอบสุขภาพบริการอัตโนมัติและกลไกการรีสตาร์ท

2. **AI-Driven Analysis**  
   - ใช้ Machine Learning ในการวิเคราะห์พฤติกรรมผู้โจมตี  
   - ทำนายการโจมตีในอนาคตด้วยโมเดล Time-Series
   - ระบบลูปข้อมูลย้อนกลับอัตโนมัติระหว่าง AI และระบบ honeypot
   - ประมวลผลข้อเสนอแนะการตอบโต้แบบเรียลไทม์

3. **ระบบข่าวกรองภัยคุกคาม (Threat Intelligence)**
   - รวบรวมข้อมูลภัยคุกคามจากแหล่งภายนอกอัตโนมัติ
   - อัปเดตฐานข้อมูลภัยคุกคามเป็นระยะ
   - ประเมินความน่าเชื่อถือและระดับอันตรายของ IP ที่น่าสงสัย

4. **Countermeasures**  
   - ตัวเลือกสำหรับการโจมตีกลับ เช่น การใช้ exploit หรือการส่งข้อมูลปลอม
   - ตั้งค่าการบล็อก IP ผ่าน firewall อัตโนมัติ
   - ระบบการตอบโต้อัจฉริยะตามระดับความรุนแรงของการโจมตี

5. **การเก็บข้อมูลเชิงลึก (Metrics)**
   - เก็บสถิติการโจมตีเชิงลึก เช่น จำนวนการโจมตีต่อชั่วโมง, IP ที่ไม่ซ้ำกัน
   - ติดตามการใช้ทรัพยากรของระบบ เช่น CPU และหน่วยความจำ
   - บันทึกระยะเวลาทำงานและสถิติประสิทธิภาพ

6. **แดชบอร์ดสำหรับการตรวจสอบ**  
   - แสดงผลข้อมูลแบบ real-time ผ่าน Grafana และ Kibana
   - API สำหรับการติดตามสถานะระบบและควบคุมระยะไกล
   - แสดงผลสถานะบริการและการแจ้งเตือนเมื่อมีปัญหา

---

## สถาปัตยกรรมระบบ

### 1. โครงสร้างหลักของ ShadowNet
```
ShadowNet/
├── cmd/                # โค้ดหลักสำหรับเริ่มต้นระบบ
├── config/             # ไฟล์และโค้ดการตั้งค่า
├── honeypot/           # โมดูล honeypot แต่ละประเภท
├── analyzer/           # ระบบวิเคราะห์พฤติกรรม
├── ai/                 # โมดูล AI และ ML
├── db/                 # การเชื่อมต่อฐานข้อมูลและการจัดการ
├── utils/              # เครื่องมือและฟังก์ชันสนับสนุน
└── countermeasures/    # โมดูลการตอบโต้ผู้โจมตี
```

### 2. การทำงานของระบบ
1. **การเริ่มต้น**
   - โหลดการตั้งค่าจากไฟล์ YAML ตามสภาพแวดล้อม
   - เชื่อมต่อฐานข้อมูลพร้อมกลไกการลองใหม่
   - เริ่มต้น honeypot ทั้งหมดตามการตั้งค่า

2. **การรับมือการโจมตี**
   - บันทึกรายละเอียดการโจมตีลงในฐานข้อมูล
   - วิเคราะห์พฤติกรรมด้วย AI แบบเรียลไทม์
   - ตัดสินใจว่าจะตอบโต้อย่างไรตามคำแนะนำของ AI

3. **การติดตามและรายงานผล**
   - API HTTP สำหรับการติดตามสถานะระบบ
   - ส่งข้อมูลไปยัง Elasticsearch เพื่อการวิเคราะห์
   - แสดงแดชบอร์ดสรุปผ่าน Kibana และ Grafana

---

## การติดตั้งและใช้งาน

### 1. ความต้องการของระบบ
- **ภาษาโปรแกรม**: Go (1.20+), Python (3.8+)  
- **ฐานข้อมูล**: PostgreSQL  
- **เครื่องมือเสริม**: Elasticsearch, Kibana, Grafana  
- **สิทธิ์การใช้งาน**: ต้องใช้งานด้วยสิทธิ์ root เพื่อตั้งค่า firewall และเรียกใช้ honeypot บางประเภท  

---

### 2. การติดตั้ง

#### 2.1 ติดตั้ง Dependency
```bash
# Go dependencies
go get github.com/gin-gonic/gin
go get github.com/coreos/go-iptables
go get github.com/jackc/pgx/v4
go get gopkg.in/yaml.v2
go get golang.org/x/crypto/ssh
go get golang.org/x/net/context

# Python dependencies
pip install tensorflow scikit-learn gym elasticsearch pandas
```

#### 2.2 ตั้งค่าฐานข้อมูล PostgreSQL
1. สร้างฐานข้อมูล:
   ```sql
   CREATE DATABASE shadownet;
   ```
2. สร้างตารางสำหรับเก็บข้อมูลการโจมตี:
   ```sql
   CREATE TABLE attacks (
       id SERIAL PRIMARY KEY,
       username TEXT,
       password TEXT,
       service TEXT,
       ip_address TEXT,
       timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       attack_vector TEXT,
       payload BYTEA,
       session_duration INTEGER
   );
   
   CREATE TABLE threat_intel (
       id SERIAL PRIMARY KEY,
       ip_address TEXT,
       reputation FLOAT,
       categories TEXT[],
       last_updated TIMESTAMP,
       source TEXT
   );
   ```

#### 2.3 ตั้งค่า Elasticsearch และ Kibana
1. ติดตั้ง Elasticsearch และ Kibana:
   ```bash
   docker-compose up -d
   ```
2. สร้าง index ใน Kibana: `attacks-*` และ `threats-*`

---

### 3. การเริ่มต้นใช้งาน

#### 3.1 แก้ไขไฟล์ config (`config/config.yaml`)
```yaml
honeypots:
  ssh_port: 2222
  http_port: 8080
  ftp_port: 2121
  rdp_port: 3389
  smb_port: 445
  modbus_port: 502
  mqtt_port: 1883
database:
  host: "localhost"
  port: 5432
  user: "postgres"
  password: "yourpassword"
  dbname: "shadownet"
ai:
  model_path: "ai/attack_classifier.pkl"
  feedback_interval: 300  # seconds
countermeasures:
  enable_exploits: false  # เปิดใช้งานหากต้องการโจมตีกลับ
  auto_block_threshold: 0.8  # บล็อก IP เมื่อคะแนนความเสี่ยงสูงกว่านี้
api:
  port: 8000  # พอร์ตสำหรับ API การติดตามระบบ
```

#### 3.2 เริ่มระบบ ShadowNet
```bash
go run cmd/main.go
```
หรือสร้างไฟล์ไบนารีและรัน:
```bash
go build -o shadownet cmd/main.go
sudo ./shadownet
```

#### 3.3 การใช้งาน Docker (ทางเลือก)
```bash
docker build -t shadownet .
docker run -p 2222:2222 -p 8080:8080 -p 2121:2121 -p 3389:3389 -p 445:445 -p 502:502 -p 1883:1883 -p 8000:8000 --name shadownet shadownet
```

---

### 4. การทดสอบ
1. **จำลองการโจมตี SSH**:
   ```bash
   ssh admin@localhost -p 2222
   ```
2. **จำลองการโจมตี RDP/SMB**:
   ```bash
   nmap -p 3389,445 localhost
   ```
3. **ตรวจสอบการทำงานของ API**:
   ```bash
   curl http://localhost:8000/health
   curl http://localhost:8000/services
   curl http://localhost:8000/metrics
   ```
4. **ตรวจสอบ log**:
   - ดู log ใน PostgreSQL:
     ```sql
     SELECT * FROM attacks;
     ```
   - ดูแดชบอร์ดใน Kibana/Grafana

---

## การพัฒนาต่อ
1. **เพิ่มโปรโตคอล honeypot**:
   - เช่น Telnet, SNMP, หรือโปรโตคอลเฉพาะทาง IoT  
2. **พัฒนา AI Model**:
   - เพิ่มความแม่นยำในการวิเคราะห์พฤติกรรมผู้โจมตี
   - เพิ่มเทคนิค Deep Learning สำหรับการตรวจจับรูปแบบที่ซับซ้อน
3. **เพิ่มความสามารถ Countermeasures**:
   - เช่น การใช้ Metasploit Framework หรือการสร้าง payload ที่ซับซ้อนขึ้น
4. **ปรับปรุงประสิทธิภาพ**:
   - ใช้เทคนิค concurrency ที่มีประสิทธิภาพมากขึ้น
   - ปรับปรุงการจัดการหน่วยความจำและทรัพยากร

---

## การแก้ไขปัญหาทั่วไป

### 1. ระบบ honeypot ไม่สามารถเริ่มต้นได้
- ตรวจสอบว่าพอร์ตไม่ถูกใช้งานโดยบริการอื่น: `netstat -tulpn | grep <port>`
- ตรวจสอบสิทธิ์ในการรัน (ต้องใช้สิทธิ์ root สำหรับพอร์ตต่ำกว่า 1024)
- ตรวจสอบการตั้งค่าในไฟล์ config.yaml

### 2. การเชื่อมต่อฐานข้อมูลล้มเหลว
- ตรวจสอบว่า PostgreSQL กำลังทำงาน: `systemctl status postgresql`
- ตรวจสอบการตั้งค่าฐานข้อมูลในไฟล์ config.yaml
- ตรวจสอบว่าฐานข้อมูลและตารางถูกสร้างแล้ว

### 3. API ไม่ตอบสนอง
- ตรวจสอบพอร์ตของ API: `netstat -tulpn | grep <api_port>`
- ตรวจสอบ log หลักสำหรับข้อผิดพลาด

---

## คำเตือน
⚠️ **ใช้งานในสภาพแวดล้อมที่ควบคุมได้เท่านั้น**  
- การเปิดใช้งาน honeypot บนเน็ตเวิร์กจริงอาจทำให้ถูกโจมตีโดยผู้ไม่ประสงค์ดี  
- การใช้งานฟีเจอร์โจมตีกลับอาจผิดกฎหมายในบางประเทศ  

หากมีคำถามเพิ่มเติม โปรดติดต่อผู้พัฒนา หรือศึกษาเอกสารเพิ่มเติมในโค้ดและ README นี้

---

## ระบบการจัดการเหตุการณ์

1. **ระดับความรุนแรง**
   - **ต่ำ**: การสแกนพอร์ต, การเข้าถึงไม่สำเร็จ 1-2 ครั้ง
   - **กลาง**: การพยายาม brute force, การตรวจสอบช่องโหว่เชิงลึก
   - **สูง**: การพยายามใช้ exploit, การเข้าถึงสำเร็จ

2. **การตอบสนอง**
   - ระดับต่ำ: เก็บข้อมูลเท่านั้น
   - ระดับกลาง: เก็บข้อมูลและบล็อก IP ชั่วคราว
   - ระดับสูง: เก็บข้อมูล, บล็อก IP ถาวร, แจ้งเตือนผู้ดูแล

3. **การรายงาน**
   - รายงานประจำวัน: สรุปการโจมตีทั้งหมด
   - รายงานการแจ้งเตือนทันที: สำหรับเหตุการณ์ระดับสูง
   - การวิเคราะห์แนวโน้ม: รายงานประจำเดือนเกี่ยวกับแนวโน้มการโจมตี

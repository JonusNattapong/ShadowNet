# ShadowNet: ระบบ Honeypot และ AI เพื่อการป้องกันและวิเคราะห์การโจมตีทางไซเบอร์

## จุดประสงค์ของโครงการ
ShadowNet เป็นระบบที่ออกแบบมาเพื่อล่อผู้โจมตีให้เข้ามาใน "กับดัก" (honeypot) ซึ่งเป็นระบบปลอมที่ดูเหมือนจริง จากนั้นจะทำการเก็บข้อมูลพฤติกรรมของผู้โจมตี วิเคราะห์รูปแบบการโจมตี และใช้ AI เพื่อปรับปรุงกลยุทธ์การป้องกัน นอกจากนี้ยังสามารถตอบโต้ผู้โจมตีได้ (ถ้าเปิดใช้งาน)

### ฟีเจอร์หลัก
1. **Honeypot Servers**  
   - รองรับโปรโตคอลหลากหลาย เช่น SSH, HTTP, FTP, RDP, SMB, Modbus, และ MQTT  
   - จำลองการทำงานของบริการจริงเพื่อดึงดูดผู้โจมตี  

2. **AI-Driven Analysis**  
   - ใช้ Machine Learning ในการวิเคราะห์พฤติกรรมผู้โจมตี  
   - ทำนายการโจมตีในอนาคตด้วยโมเดล Time-Series  

3. **Countermeasures**  
   - ตัวเลือกสำหรับการโจมตีกลับ เช่น การใช้ exploit หรือการส่งข้อมูลปลอม  

4. **แดชบอร์ดสำหรับการตรวจสอบ**  
   - แสดงผลข้อมูลแบบ real-time ผ่าน Grafana และ Kibana  

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

# Python dependencies
pip install tensorflow scikit-learn gym elasticsearch
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
       timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );
   ```

#### 2.3 ตั้งค่า Elasticsearch และ Kibana
1. ติดตั้ง Elasticsearch และ Kibana:
   ```bash
   docker run -d --name elasticsearch -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" elasticsearch:7.10.1
   docker run -d --name kibana -p 5601:5601 --link elasticsearch:elasticsearch kibana:7.10.1
   ```
2. สร้าง index ใน Kibana: `attacks-*`

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
database:
  host: "localhost"
  port: 5432
  user: "postgres"
  password: "yourpassword"
  dbname: "shadownet"
ai:
  model_path: "ai/attack_classifier.pkl"
countermeasures:
  enable_exploits: false  # เปิดใช้งานหากต้องการโจมตีกลับ
```

#### 3.2 เริ่มระบบ ShadowNet
```bash
go run cmd/main.go
```

---

### 4. การทดสอบ
1. **Simulate SSH Attack**:
   ```bash
   ssh admin@localhost -p 2222
   ```
2. **Simulate RDP/SMB Attack**:
   ```bash
   nmap -p 3389,445 localhost
   ```
3. **ตรวจสอบ log**:
   - ดู log ใน PostgreSQL:
     ```sql
     SELECT * FROM attacks;
     ```
   - ดูแดชบอร์ดใน Kibana/Grafana

---

## การใช้งาน Dashboard
1. **Kibana**:
   - URL: `http://localhost:5601`  
   - Visualizations: Pie chart สำหรับประเภทการโจมตี, Time series สำหรับความถี่  

2. **Grafana**:
   - URL: `http://localhost:3000`  
   - Panels: Real-time attack counter, ML predictions, Heatmap  

---

## การพัฒนาต่อ
1. **เพิ่มโปรโตคอล honeypot**:
   - เช่น Telnet, SNMP, หรือโปรโตคอลเฉพาะทาง IoT  
2. **พัฒนา AI Model**:
   - เพิ่มความแม่นยำในการวิเคราะห์พฤติกรรมผู้โจมตี  
3. **เพิ่มความสามารถ Countermeasures**:
   - เช่น การใช้ Metasploit Framework หรือการสร้าง payload ที่ซับซ้อนขึ้น  

---

## คำเตือน
⚠️ **ใช้งานในสภาพแวดล้อมที่ควบคุมได้เท่านั้น**  
- การเปิดใช้งาน honeypot บนเน็ตเวิร์กจริงอาจทำให้ถูกโจมตีโดยผู้ไม่ประสงค์ดี  
- การใช้งานฟีเจอร์โจมตีกลับอาจผิดกฎหมายในบางประเทศ  

หากมีคำถามเพิ่มเติม โปรดติดต่อผู้พัฒนา หรือศึกษาเอกสารเพิ่มเติมในโค้ดและ README นี้

---

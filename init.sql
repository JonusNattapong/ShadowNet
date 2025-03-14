-- สคริปต์สำหรับการสร้างฐานข้อมูลเริ่มต้นสำหรับ ShadowNet

-- สร้างตารางเก็บข้อมูลการโจมตี
CREATE TABLE IF NOT EXISTS attacks (
    id SERIAL PRIMARY KEY,
    username TEXT,
    password TEXT,
    service TEXT,
    ip_address TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    attack_vector TEXT,
    payload BYTEA,
    session_duration INTEGER,
    severity INT DEFAULT 1 -- 1=ต่ำ, 2=กลาง, 3=สูง
);

-- สร้างตารางเก็บข้อมูลภัยคุกคาม
CREATE TABLE IF NOT EXISTS threat_intel (
    id SERIAL PRIMARY KEY,
    ip_address TEXT UNIQUE,
    reputation FLOAT,
    categories TEXT[],
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source TEXT
);

-- สร้างตารางเก็บข้อมูลการตอบโต้
CREATE TABLE IF NOT EXISTS countermeasures (
    id SERIAL PRIMARY KEY,
    ip_address TEXT,
    action TEXT,
    reason TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN
);

-- สร้างตารางเก็บข้อมูลสถิติ
CREATE TABLE IF NOT EXISTS metrics (
    id SERIAL PRIMARY KEY,
    metric_name TEXT,
    metric_value FLOAT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- สร้าง index สำหรับการค้นหาที่รวดเร็ว
CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(ip_address);
CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp);
CREATE INDEX IF NOT EXISTS idx_attacks_service ON attacks(service);
CREATE INDEX IF NOT EXISTS idx_threat_intel_ip ON threat_intel(ip_address);

-- สร้าง view สำหรับการดูข้อมูลที่สำคัญ
CREATE OR REPLACE VIEW attack_summary AS
SELECT 
    date_trunc('day', timestamp) AS day,
    service,
    COUNT(*) AS attack_count,
    COUNT(DISTINCT ip_address) AS unique_ips
FROM 
    attacks
GROUP BY 
    day, service
ORDER BY 
    day DESC, attack_count DESC;

-- สร้าง function สำหรับการล้างข้อมูลเก่า
CREATE OR REPLACE FUNCTION cleanup_old_attacks(days_to_keep INT)
RETURNS void AS $$
BEGIN
    DELETE FROM attacks WHERE timestamp < NOW() - (days_to_keep * INTERVAL '1 day');
END;
$$ LANGUAGE plpgsql;

-- เพิ่มข้อมูลเริ่มต้น (ถ้าจำเป็น)
INSERT INTO threat_intel (ip_address, reputation, categories, source)
VALUES 
('123.45.67.89', 0.95, ARRAY['botnet', 'bruteforce'], 'initial-seed'),
('98.76.54.32', 0.85, ARRAY['scanner', 'malware'], 'initial-seed')
ON CONFLICT DO NOTHING;

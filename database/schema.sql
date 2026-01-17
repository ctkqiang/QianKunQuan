-- CVE漏洞数据库表结构
CREATE TABLE cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE NOT NULL,
    description TEXT,
    cvss_score REAL,
    cvss_severity TEXT,
    published DATE,
    modified DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE affected_software (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    version TEXT,
    version_end TEXT,
    cpe TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
);

-- 创建索引
CREATE INDEX idx_cve_id ON cves(cve_id);
CREATE INDEX idx_product ON affected_software(product);
CREATE INDEX idx_vendor ON affected_software(vendor);
CREATE INDEX idx_cve_product ON affected_software(cve_id, product);
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import json, os, threading, time, random, sqlite3, io, hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = 'falconx-esas-secret-2025'
DB = os.path.join(os.path.dirname(__file__), 'esas.db')

# ═══════════════════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════════════════
def get_db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c

# ═══════════════════════════════════════════════════════════════════
#  CVE / VULN LIBRARY  — 14 real-world CVEs with full metadata
# ═══════════════════════════════════════════════════════════════════
VULN_LIBRARY = [
    # (cve_id, title, severity, cvss, service, description, port, category)
    ('CVE-2024-3094',  'XZ Utils Supply Chain Backdoor',         'critical', 10.0, 'SSH / liblzma',    'Malicious code injected into XZ Utils 5.6.0-5.6.1 creates a backdoor in sshd on systemd systems, allowing unauthenticated remote access.', 22,   'supply-chain'),
    ('CVE-2024-0982',  'OpenSSL Heap Buffer Overflow RCE',       'critical',  9.8, 'OpenSSL 3.x',      'Heap buffer overflow in OpenSSL < 3.3.1 triggered by a malicious X.509 certificate. Allows unauthenticated remote code execution.', 443,  'crypto'),
    ('CVE-2024-21413', 'Microsoft Outlook NTLM Leak',            'critical',  9.8, 'Outlook / SMTP',   'A specially crafted hyperlink in Outlook bypasses Protected View and triggers automatic NTLM authentication, leaking Net-NTLMv2 credential hashes.', 25,   'windows'),
    ('CVE-2023-44487',  'HTTP/2 Rapid Reset DoS',                'critical',  9.3, 'nginx / Apache',   'Rapid stream-reset attack via HTTP/2 HEADERS+RST_STREAM cycle floods the server, causing a denial of service. Affects most web servers.', 443,  'web'),
    ('CVE-2024-1234',  'MySQL Exposed with Default Credentials', 'critical',  9.1, 'MySQL 5.7/8.0',    'MySQL instance exposed with unchanged vendor default root password. Grants unauthenticated full database access from the network.', 3306, 'database'),
    ('CVE-2024-6387',  'OpenSSH regreSSHion Race Condition RCE', 'critical',  8.1, 'OpenSSH < 9.8p1',  'Race condition in OpenSSH signal handler allows unauthenticated remote code execution as root on glibc-based Linux systems.', 22,   'ssh'),
    ('CVE-2023-5678',  'RDP Exposed to Internet (No VPN)',       'high',      8.2, 'RDP / Port 3389',  'Remote Desktop Protocol is directly exposed to the internet without a VPN gateway. Enables brute-force attacks and potential RCE exploits.', 3389,'network'),
    ('CVE-2024-2201',  'Spectre v2 Kernel Mitigation Bypass',   'high',      7.9, 'Linux Kernel',     'Branch history injection (BHI) attack bypasses existing Spectre v2 mitigations in the Linux kernel. Allows info leak across privilege boundaries.', 0,    'kernel'),
    ('CVE-2023-38545', 'libcurl SOCKS5 Heap Buffer Overflow',   'high',      7.5, 'libcurl < 8.4.0',  'Oversized hostname in a SOCKS5 connection triggers a heap-based buffer overflow. Can lead to code execution in the curl client or dependent apps.', 1080,'network'),
    ('CVE-2023-6129',  'OpenSSL POLY1305 MAC Corruption',       'high',      7.4, 'OpenSSL / PowerPC','Incorrect POLY1305 MAC computation on PowerPC / AltiVec CPU paths corrupts the XMM register save area, leading to state corruption.', 443, 'crypto'),
    ('CVE-2024-23897', 'Jenkins CLI Unauthenticated File Read', 'medium',    6.2, 'Jenkins 2.441',    'The Jenkins CLI argument parser allows any user to read arbitrary files from the Jenkins controller filesystem, including secrets.', 8080,'ci-cd'),
    ('CVE-2024-0985',  'PostgreSQL Non-Superuser Priv Escalation','medium',  6.4, 'PostgreSQL 15',    'A non-superuser can trigger a row security policy defined by a superuser via the MERGE SQL command, bypassing row-level security checks.', 5432,'database'),
    ('CVE-2023-50782', 'python-cryptography RSA Timing Oracle', 'medium',    5.9, 'python-cryptography','Bleichenbacher-style timing side channel in the RSA decryption path. An attacker can extract private key material over many measurements.', 0,  'crypto'),
    ('CVE-2024-0232',  'SQLite NULL Pointer Dereference Crash',  'low',      2.8, 'SQLite 3.44',      'A specially crafted SQL SELECT statement triggers a NULL pointer dereference in the SQLite query engine, causing a crash (denial of service).', 0, 'database'),
]

# Per-target-type vulnerability affinity — which CVEs are most likely per target class
TARGET_VULN_AFFINITY = {
    'network': ['CVE-2024-3094','CVE-2024-6387','CVE-2023-5678','CVE-2024-2201','CVE-2023-38545','CVE-2024-1234','CVE-2024-0982','CVE-2023-6129','CVE-2024-0232'],
    'cloud':   ['CVE-2024-0982','CVE-2023-44487','CVE-2024-21413','CVE-2024-1234','CVE-2024-23897','CVE-2024-0985','CVE-2023-50782','CVE-2024-6387'],
    'app':     ['CVE-2023-44487','CVE-2024-23897','CVE-2024-21413','CVE-2024-0985','CVE-2023-50782','CVE-2024-0982','CVE-2024-6387','CVE-2024-0232'],
}

# ═══════════════════════════════════════════════════════════════════
#  COMPLIANCE CHECKS
# ═══════════════════════════════════════════════════════════════════
ISO_CHECKS = [
    ('A.5.1', 'Information Security Policies',   'Security policy document reviewed by management within 12 months'),
    ('A.6.1', 'Organization of Information Security','Roles and responsibilities for information security formally assigned'),
    ('A.7.1', 'HR Security — Prior to Employment','Background verification checks on all candidates with system access'),
    ('A.8.1', 'Responsibility for Assets',        'All information assets inventoried, classified, and assigned an owner'),
    ('A.9.1', 'Access Control Policy',            'Role-based access control policy documented and enforced'),
    ('A.9.2', 'User Access Provisioning',         'Formal access request and approval records for all user accounts'),
    ('A.9.3', 'MFA for Privileged Access',        'Multi-factor authentication enforced on all privileged accounts'),
    ('A.10.1','Cryptographic Controls',           'AES-256 encryption at rest and TLS 1.3 in transit enforced'),
    ('A.12.1','Documented Operating Procedures',  'Operational runbooks documented and reviewed for critical services'),
    ('A.12.3','Information Backup',               'Daily encrypted backups with quarterly restoration testing'),
    ('A.12.6','Management of Technical Vulnerabilities','Patches applied: Critical ≤24h, High ≤7d, Medium ≤30d'),
    ('A.13.1','Network Security Controls',        'Network segmentation via VLANs; IDS/IPS deployed and monitored'),
    ('A.14.2','Security in Development Processes','SAST/DAST tools integrated in CI/CD pipeline; peer code review mandatory'),
    ('A.16.1','Management of Security Incidents', 'Incident response plan documented, tested annually, with assigned roles'),
    ('A.18.1','Compliance with Legal Requirements','Data protection legislation compliance assessed and documented'),
]

NIST_CHECKS = [
    ('ID.AM-1','Asset Inventory',           'Physical devices and systems documented in asset inventory'),
    ('ID.AM-2','Software Inventory',        'Software platforms and applications catalogued with versions'),
    ('ID.RA-1','Vulnerability Assessment',  'Vulnerability assessments conducted on schedule for all assets'),
    ('ID.RA-3','Threat Intelligence',       'Internal and external threats identified and documented'),
    ('PR.AC-1','Identity Management',       'Identities and credentials issued only to authorized entities'),
    ('PR.AC-4','Access Permissions',        'Access permissions managed with minimum necessary privilege'),
    ('PR.DS-1','Data-at-Rest Protection',   'Sensitive data encrypted at rest per classification policy'),
    ('PR.DS-2','Data-in-Transit Security',  'All data transmissions encrypted with TLS 1.2 or higher'),
    ('DE.CM-1','Network Monitoring',        'Network traffic monitored continuously for anomalous activity'),
    ('DE.AE-2','Event Analysis',            'Security events correlated and analysed to detect attack patterns'),
    ('RS.RP-1','Incident Response',         'Response plans executed and tested during or after incidents'),
    ('RC.RP-1','Recovery Planning',         'Recovery plans executed to restore operations after incidents'),
]

PCI_CHECKS = [
    ('1.1', 'Firewall Configuration',       'Install and maintain network security controls to protect cardholder data'),
    ('2.1', 'No Vendor Defaults',           'Vendor-supplied default passwords and settings removed or changed'),
    ('3.4', 'PAN Rendered Unreadable',      'Primary account numbers rendered unreadable in stored data'),
    ('4.1', 'Encryption in Transit',        'Strong cryptography used when transmitting cardholder data over networks'),
    ('6.3', 'Security Patch Management',    'All system components protected from known vulnerabilities via patching'),
    ('7.1', 'Access Restriction',           'Access to system components restricted to only what is business-required'),
    ('8.2', 'User Identification',          'Unique IDs assigned to each user accessing system components'),
    ('10.1','Audit Logging',                'Audit logs enabled and protected to track access to cardholder data'),
    ('11.2','Vulnerability Scanning',       'Internal and external scans run quarterly and after significant changes'),
    ('12.1','Security Policy',              'Security policy maintained, published and distributed to all personnel'),
]

# Per-target compliance profiles (pass_probability per control, based on target context)
COMPLIANCE_PROFILES = {
    'network_production': {'ISO27001': 0.72, 'NIST': 0.68, 'PCI-DSS': 0.65},
    'network_dev':        {'ISO27001': 0.50, 'NIST': 0.55, 'PCI-DSS': 0.40},
    'cloud_production':   {'ISO27001': 0.78, 'NIST': 0.75, 'PCI-DSS': 0.70},
    'cloud_dev':          {'ISO27001': 0.55, 'NIST': 0.60, 'PCI-DSS': 0.45},
    'app_production':     {'ISO27001': 0.65, 'NIST': 0.62, 'PCI-DSS': 0.58},
    'app_dev':            {'ISO27001': 0.48, 'NIST': 0.52, 'PCI-DSS': 0.38},
    'default':            {'ISO27001': 0.60, 'NIST': 0.58, 'PCI-DSS': 0.55},
}

REMEDIATION = {
    'CVE-2024-3094':  'Downgrade XZ Utils to ≤5.4.5 immediately. Remove liblzma 5.6.0/5.6.1 packages. Check: xz --version. Audit authorized SSH keys: cat ~/.ssh/authorized_keys. Restart sshd after fix.',
    'CVE-2024-0982':  'Upgrade OpenSSL to ≥3.3.1. Run: openssl version to verify. Restart all services using OpenSSL (nginx, apache, postfix). Check distributions for backport patches.',
    'CVE-2024-21413': 'Apply Microsoft patch KB5034763. Disable automatic NTLM authentication via Group Policy. Configure Outlook to use Protected View for all external content.',
    'CVE-2023-44487': 'Upgrade nginx ≥1.25.3 or Apache ≥2.4.58. Enable HTTP/2 request rate limiting. For nginx: http2_max_requests 100; For Apache: H2MaxSessionRequests 100. Deploy WAF rule.',
    'CVE-2024-1234':  'Change MySQL root password NOW: ALTER USER root@localhost IDENTIFIED BY "StrongPass!"; Disable remote root: bind-address=127.0.0.1 in my.cnf. Enable mysql_secure_installation.',
    'CVE-2024-6387':  'Upgrade OpenSSH to ≥9.8p1. Workaround: set LoginGraceTime 0 in sshd_config (disables auth timeout). Restart sshd. Verify: ssh -V.',
    'CVE-2023-5678':  'Block RDP (3389) at perimeter firewall immediately. Deploy VPN gateway (OpenVPN/WireGuard). Enable NLA (Network Level Authentication). Consider RDP gateway with MFA.',
    'CVE-2024-2201':  'Apply kernel update ≥6.8 with BHI mitigations. Verify: cat /sys/devices/system/cpu/vulnerabilities/spectre_v2. Disable unprivileged eBPF if not needed.',
    'CVE-2023-38545': 'Upgrade libcurl to ≥8.4.0. Run: curl --version. Rebuild any apps statically linked to older libcurl. Review all SOCKS5 proxy configurations for hostname length.',
    'CVE-2023-6129':  'Upgrade OpenSSL to ≥3.2.1. Issue primarily affects PowerPC with AltiVec. Verify CPU type and confirm patch level: openssl version -a.',
    'CVE-2024-23897': 'Upgrade Jenkins to ≥2.442. Disable CLI access if unused: JENKINS_ARGS="--argumentsRealm.roles.user=...". Restrict Jenkins behind authentication proxy with IP allowlist.',
    'CVE-2024-0985':  'Upgrade PostgreSQL to ≥15.6 or ≥16.2. Review all MERGE statements with row-level security. Run: SELECT version(); after upgrade to confirm.',
    'CVE-2023-50782': 'Upgrade python-cryptography to ≥42.0.0: pip install cryptography --upgrade. Audit code for RSA decryption usage. Consider migrating to X25519 key exchange.',
    'CVE-2024-0232':  'Upgrade SQLite to ≥3.45.0. Validate all user-supplied SQL input. Compile with SQLITE_USE_ALLOCA=0. Most distributions have patched this in recent updates.',
}

DEMO_TARGETS = {
    'network': [
        {'label':'Production LAN (192.168.10.0/24)',  'value':'192.168.10.0/24',  'env':'production'},
        {'label':'Development LAN (192.168.1.0/24)',  'value':'192.168.1.0/24',   'env':'dev'},
        {'label':'Internal DMZ (10.0.50.0/24)',       'value':'10.0.50.0/24',     'env':'production'},
        {'label':'Build Network (10.50.0.0/16)',      'value':'10.50.0.0/16',     'env':'dev'},
        {'label':'Legacy Segment (172.16.0.0/24)',    'value':'172.16.0.0/24',    'env':'dev'},
        {'label':'App Server (192.168.1.10)',         'value':'192.168.1.10',     'env':'production'},
        {'label':'DB Server (192.168.1.44)',          'value':'192.168.1.44',     'env':'production'},
        {'label':'Jenkins CI (192.168.1.60)',         'value':'192.168.1.60',     'env':'dev'},
    ],
    'cloud': [
        {'label':'AWS Production (ap-south-1)',       'value':'aws-prod-123456789','env':'production'},
        {'label':'AWS Development (ap-south-1)',      'value':'aws-dev-987654321', 'env':'dev'},
        {'label':'AWS Staging (ap-south-1)',          'value':'aws-stg-111222333', 'env':'dev'},
    ],
    'app': [
        {'label':'Corporate Web App (app.corp.local)','value':'https://app.corp.local',     'env':'production'},
        {'label':'REST API Gateway (api.corp.local)', 'value':'https://api.corp.local',     'env':'production'},
        {'label':'Auth/SSO Service (auth.corp.local)','value':'https://auth.corp.local',    'env':'production'},
        {'label':'Jenkins CI (ci.corp.local)',        'value':'https://ci.corp.local',      'env':'dev'},
        {'label':'Grafana Monitor (monitor.corp.local)','value':'https://monitor.corp.local','env':'dev'},
        {'label':'MinIO Storage (storage.corp.local)','value':'https://storage.corp.local', 'env':'dev'},
    ],
}

DEMO_CLOUD = {
    'ec2_instances': [
        {'id':'i-0a1b2c3d4e5f','name':'prod-web-01','type':'t3.medium','ip':'10.0.1.45','pub_ip':'54.92.148.200','az':'ap-south-1a','state':'running','os':'Ubuntu 22.04 LTS','security':'warning'},
        {'id':'i-1b2c3d4e5f6a','name':'prod-web-02','type':'t3.medium','ip':'10.0.1.46','pub_ip':'52.66.33.11', 'az':'ap-south-1b','state':'running','os':'Ubuntu 22.04 LTS','security':'ok'},
        {'id':'i-2c3d4e5f6a7b','name':'prod-db-01', 'type':'r5.large', 'ip':'10.0.2.78','pub_ip':'',            'az':'ap-south-1a','state':'running','os':'Amazon Linux 2',   'security':'ok'},
        {'id':'i-3d4e5f6a7b8c','name':'ci-jenkins',  'type':'t3.large', 'ip':'10.0.3.12','pub_ip':'13.235.12.44','az':'ap-south-1a','state':'running','os':'Ubuntu 20.04 LTS','security':'critical'},
        {'id':'i-4e5f6a7b8c9d','name':'dev-build-01','type':'t3.small', 'ip':'10.1.0.5', 'pub_ip':'',            'az':'ap-south-1a','state':'stopped','os':'Ubuntu 22.04 LTS','security':'ok'},
    ],
    's3_buckets': [
        {'name':'prod-app-assets',    'public':False,'versioning':True, 'encryption':True, 'size_gb':42.3,  'risk':'ok'},
        {'name':'prod-db-backups',    'public':False,'versioning':True, 'encryption':True, 'size_gb':185.6, 'risk':'ok'},
        {'name':'dev-test-uploads',   'public':True, 'versioning':False,'encryption':False,'size_gb':3.1,   'risk':'critical'},
        {'name':'ci-build-artifacts', 'public':False,'versioning':False,'encryption':True, 'size_gb':22.8,  'risk':'warning'},
        {'name':'logs-archive-2024',  'public':False,'versioning':False,'encryption':True, 'size_gb':411.0, 'risk':'ok'},
    ],
    'rds_instances': [
        {'id':'prod-mysql-01',  'engine':'MySQL 8.0',      'type':'db.r5.large', 'multi_az':True, 'encrypted':True, 'public':False,'risk':'ok'},
        {'id':'dev-postgres-01','engine':'PostgreSQL 15.5','type':'db.t3.medium','multi_az':False,'encrypted':False,'public':True, 'risk':'critical'},
    ],
    'iam_findings': [
        {'user':'deploy-bot',    'finding':'Access key not rotated — last rotation 187 days ago','severity':'high',    'key_id':'AKIAIOSFODNN7EXAMPLE'},
        {'user':'dev-temp-01',   'finding':'AdministratorAccess policy attached directly to user','severity':'critical','key_id':'AKIAI44QH8DHBEXAMPLE'},
        {'user':'backup-service','finding':'MFA not enabled for this programmatic access user',  'severity':'medium',  'key_id':'AKIAIOSFODNN5EXAMPLE'},
    ],
}

# ═══════════════════════════════════════════════════════════════════
#  DETERMINISTIC SCAN ENGINE
#  Results differ per target — seeded by target hash for consistency
# ═══════════════════════════════════════════════════════════════════
def get_hosts_for_target(target, target_type):
    """Return realistic, target-specific host list."""
    host_map = {
        '192.168.1.0/24':    ['192.168.1.5','192.168.1.10','192.168.1.12','192.168.1.44','192.168.1.60','192.168.1.101','192.168.1.112','192.168.1.130'],
        '192.168.10.0/24':   ['192.168.10.5','192.168.10.12','192.168.10.44','192.168.10.60','192.168.10.101','192.168.10.115','192.168.10.130'],
        '10.0.50.0/24':      ['10.0.50.10','10.0.50.20','10.0.50.30','10.0.50.44','10.0.50.55'],
        '10.50.0.0/16':      ['10.50.1.10','10.50.1.25','10.50.2.8','10.50.3.44','10.50.4.200'],
        '172.16.0.0/24':     ['172.16.0.5','172.16.0.20','172.16.0.45','172.16.0.60'],
        '192.168.1.10':      ['192.168.1.10'],
        '192.168.1.44':      ['192.168.1.44'],
        '192.168.1.60':      ['192.168.1.60'],
        'aws-prod-123456789':['10.0.1.45','10.0.1.46','10.0.2.78','10.0.3.12','54.92.148.200','52.66.33.11'],
        'aws-dev-987654321': ['10.1.0.5','10.1.0.12','10.1.0.20','10.1.1.5'],
        'aws-stg-111222333': ['10.2.0.5','10.2.0.10','10.2.0.15'],
    }
    if target in host_map:
        return host_map[target]
    if target_type == 'app':
        domain = target.replace('https://','').replace('http://','')
        return [domain]
    # Auto-generate from CIDR
    try:
        base = target.split('/')[0].rsplit('.',1)[0]
        return [f'{base}.{i}' for i in [5,12,25,44,60,101]]
    except:
        return ['192.168.1.1','192.168.1.2']

def get_target_profile(target, target_type):
    """Determine environment profile for compliance scoring."""
    t = target.lower()
    is_prod = any(x in t for x in ['prod','production','192.168.10','10.0.','54.','52.','app.corp','auth.corp','api.corp'])
    is_dev  = any(x in t for x in ['dev','build','ci','192.168.1.','10.1.','10.50.','monitor','storage','172.16'])
    if is_prod:
        return f'{target_type}_production'
    elif is_dev:
        return f'{target_type}_dev'
    return 'default'

def pick_vulns_for_target(target, target_type, depth, seed_extra=0):
    """
    Pick vulnerabilities that are realistic for the given target.
    Uses a deterministic seed so re-running same target gives consistent results,
    but different targets give different results.
    """
    seed_str = f'{target}:{target_type}:{depth}:{seed_extra}'
    seed_int = int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16)
    rng = random.Random(seed_int)

    # Filter CVEs by affinity for this target type
    affinity_cves = TARGET_VULN_AFFINITY.get(target_type, [v[0] for v in VULN_LIBRARY])
    priority = [v for v in VULN_LIBRARY if v[0] in affinity_cves]
    others   = [v for v in VULN_LIBRARY if v[0] not in affinity_cves]

    # Shuffle both lists with deterministic seed
    rng.shuffle(priority)
    rng.shuffle(others)
    ordered = priority + others

    count = {'quick': 4, 'standard': 8, 'full': len(VULN_LIBRARY)}.get(depth, 8)
    return ordered[:count]

def get_compliance_results(target, target_type, depth, seed_extra=0):
    """Return deterministic per-target compliance pass/fail results."""
    profile_key = get_target_profile(target, target_type)
    profile = COMPLIANCE_PROFILES.get(profile_key, COMPLIANCE_PROFILES['default'])

    seed_str = f'compliance:{target}:{target_type}:{seed_extra}'
    seed_int = int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16)

    results = {}
    for fw, base_prob in profile.items():
        rng = random.Random(seed_int ^ hash(fw))
        checks = {'ISO27001': ISO_CHECKS, 'NIST': NIST_CHECKS, 'PCI-DSS': PCI_CHECKS}[fw]
        if depth == 'quick' and fw == 'ISO27001':
            checks = checks[:6]
        fw_results = []
        for cid, title, desc in checks:
            # Each control has a slightly varied probability
            ctrl_seed = seed_int ^ hash(cid)
            ctrl_rng  = random.Random(ctrl_seed)
            jitter    = ctrl_rng.uniform(-0.15, 0.15)
            passed    = ctrl_rng.random() < (base_prob + jitter)
            fw_results.append((cid, title, desc, passed))
        results[fw] = fw_results
    return results

# ═══════════════════════════════════════════════════════════════════
#  DATABASE INIT + DEMO SEED
# ═══════════════════════════════════════════════════════════════════
def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT DEFAULT 'viewer',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, audit_type TEXT, target_type TEXT,
            target TEXT, ports TEXT, scan_mode TEXT, scan_depth TEXT,
            aws_account TEXT, aws_services TEXT,
            status TEXT DEFAULT 'pending', progress INTEGER DEFAULT 0,
            current_step TEXT, started_at TEXT, completed_at TEXT, created_by INTEGER
        );
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER, result_type TEXT, severity TEXT,
            title TEXT, description TEXT, host TEXT, service TEXT,
            cve_id TEXT, cvss_score REAL, framework TEXT, control_id TEXT,
            status TEXT DEFAULT 'open', created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS compliance_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            framework TEXT, control_id TEXT, title TEXT,
            description TEXT, check_type TEXT, check_params TEXT,
            severity TEXT DEFAULT 'medium', enabled INTEGER DEFAULT 1,
            created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER, severity TEXT, title TEXT, message TEXT,
            channel TEXT, sent INTEGER DEFAULT 0, error_msg TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS email_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT DEFAULT 'gmail',
            smtp_host TEXT DEFAULT '', smtp_port INTEGER DEFAULT 587,
            smtp_user TEXT DEFAULT '', smtp_pass TEXT DEFAULT '',
            from_addr TEXT DEFAULT '', use_tls INTEGER DEFAULT 1,
            enabled INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS alert_recipients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            severity_filter TEXT DEFAULT 'critical,high',
            active INTEGER DEFAULT 1
        );
        """)
        if not db.execute("SELECT 1 FROM users").fetchone():
            for uname, email, role in [
                ('admin',   'admin@esas.local',   'admin'),
                ('auditor', 'auditor@esas.local', 'auditor'),
                ('viewer',  'viewer@esas.local',  'viewer'),
            ]:
                pw = {'admin':'Admin@123','auditor':'Audit@123','viewer':'View@123'}[uname]
                db.execute("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,?)",
                           (uname, email, generate_password_hash(pw), role))
            for cid,title,desc in ISO_CHECKS:
                db.execute("INSERT INTO compliance_rules(framework,control_id,title,description,check_type,check_params,severity,created_by) VALUES(?,?,?,?,?,?,?,?)",
                           ('ISO27001',cid,title,desc,'policy','{}','high',1))
            for cid,title,desc in NIST_CHECKS:
                db.execute("INSERT INTO compliance_rules(framework,control_id,title,description,check_type,check_params,severity,created_by) VALUES(?,?,?,?,?,?,?,?)",
                           ('NIST',cid,title,desc,'config','{}','medium',1))
            for cid,title,desc in PCI_CHECKS:
                db.execute("INSERT INTO compliance_rules(framework,control_id,title,description,check_type,check_params,severity,created_by) VALUES(?,?,?,?,?,?,?,?)",
                           ('PCI-DSS',cid,title,desc,'config','{}','high',1))
            db.execute("INSERT INTO email_config(provider,smtp_host,smtp_port,smtp_user,smtp_pass,from_addr,use_tls,enabled) VALUES('gmail','',587,'','','',1,0)")
            _seed_demo_scans(db)
            db.commit()
            print("✓ DB seeded: admin/Admin@123 | auditor/Audit@123 | viewer/View@123")

def _seed_demo_scans(db):
    """Seed 5 realistic historical scans — each with unique findings."""
    demo_jobs = [
        # (name, audit_type, target_type, target, depth, days_ago, seed)
        ('Q3-2025 Production Audit',      'combined',     'network', '192.168.10.0/24',   'full',     -30, 1),
        ('AWS Cloud Security Review',     'compliance',   'cloud',   'aws-prod-123456789', 'standard', -21, 2),
        ('Web App Vulnerability Scan',    'vulnerability','app',     'https://app.corp.local','standard',-14, 3),
        ('Q4-2025 Pre-Release Audit',     'combined',     'network', '192.168.1.0/24',    'standard', -7,  4),
        ('CI/CD Pipeline Security Check', 'vulnerability','app',     'https://ci.corp.local','quick',  -2,  5),
    ]
    for name,atype,ttype,target,depth,days_ago,seed in demo_jobs:
        started   = (datetime.utcnow() + timedelta(days=days_ago)).isoformat()
        completed = (datetime.utcnow() + timedelta(days=days_ago, hours=1, minutes=15)).isoformat()
        cur = db.execute("""INSERT INTO scan_jobs
            (name,audit_type,target_type,target,ports,scan_mode,scan_depth,
             aws_account,aws_services,status,progress,current_step,started_at,completed_at,created_by)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (name,atype,ttype,target,'22,80,443,3306,3389,8080','manual',depth,
             'prod-123456789' if ttype=='cloud' else '',
             json.dumps(['IAM','S3','EC2','RDS']) if ttype=='cloud' else '[]',
             'completed',100,'Scan complete',started,completed,1))
        jid = cur.lastrowid
        hosts = get_hosts_for_target(target, ttype)

        # Vulnerabilities — deterministic per target
        for cve,title,sev,cvss,service,desc,port,cat in pick_vulns_for_target(target, ttype, depth, seed):
            host = hosts[seed % len(hosts)]
            seed = (seed * 1103515245 + 12345) & 0x7fffffff  # LCG for varied host selection
            host = hosts[seed % len(hosts)]
            db.execute("""INSERT INTO scan_results
                (job_id,result_type,severity,title,description,host,service,cve_id,cvss_score,status)
                VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (jid,'vulnerability',sev,title,desc,host,service,cve,cvss,'open'))

        # Compliance — only for combined/compliance scans
        if atype in ('compliance','combined'):
            comp = get_compliance_results(target, ttype, depth, seed)
            for fw, fw_results in comp.items():
                for cid,title,desc,passed in fw_results:
                    db.execute("""INSERT INTO scan_results
                        (job_id,result_type,framework,control_id,title,description,severity,status)
                        VALUES(?,?,?,?,?,?,?,?)""",
                        (jid,'compliance',fw,cid,title,desc,'info' if passed else 'high','pass' if passed else 'fail'))

# ═══════════════════════════════════════════════════════════════════
#  EMAIL ENGINE  — simplified provider-based setup
# ═══════════════════════════════════════════════════════════════════
EMAIL_PROVIDERS = {
    'gmail':    {'host':'smtp.gmail.com',     'port':587, 'tls':1, 'note':'Use a Gmail App Password (not your main password). Enable 2FA first at myaccount.google.com.'},
    'outlook':  {'host':'smtp.office365.com', 'port':587, 'tls':1, 'note':'Use your full Microsoft email and password. Office 365 accounts may require App Password.'},
    'yahoo':    {'host':'smtp.mail.yahoo.com','port':587, 'tls':1, 'note':'Generate an App Password in Yahoo Account Security settings.'},
    'sendgrid': {'host':'smtp.sendgrid.net',  'port':587, 'tls':1, 'note':'Username is always "apikey". Password is your SendGrid API key from the dashboard.'},
    'mailgun':  {'host':'smtp.mailgun.org',   'port':587, 'tls':1, 'note':'Use SMTP credentials from your Mailgun domain settings page.'},
    'custom':   {'host':'',                   'port':587, 'tls':1, 'note':'Enter your own SMTP server details.'},
}

def get_email_cfg():
    with get_db() as db:
        return db.execute("SELECT * FROM email_config LIMIT 1").fetchone()

def send_alert_email(subject, body_html, to_addrs):
    cfg = get_email_cfg()
    if not cfg or not cfg['enabled']:
        return False, "Email alerts are disabled. Enable them in Settings → Email Alerts."
    if not cfg['smtp_host']:
        return False, "SMTP not configured. Go to Settings → Email Alerts to set up your email provider."
    if not to_addrs:
        return False, "No recipients added. Add at least one email address in Settings → Email Alerts."
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = cfg['from_addr'] or cfg['smtp_user']
        msg['To']      = ', '.join(to_addrs)
        msg.attach(MIMEText(body_html, 'html'))
        if cfg['use_tls']:
            srv = smtplib.SMTP(cfg['smtp_host'], cfg['smtp_port'], timeout=15)
            srv.ehlo(); srv.starttls(); srv.ehlo()
        else:
            srv = smtplib.SMTP_SSL(cfg['smtp_host'], cfg['smtp_port'], timeout=15)
        if cfg['smtp_user'] and cfg['smtp_pass']:
            srv.login(cfg['smtp_user'], cfg['smtp_pass'])
        srv.sendmail(msg['From'], to_addrs, msg.as_string())
        srv.quit()
        return True, 'OK'
    except smtplib.SMTPAuthenticationError:
        return False, 'Authentication failed — check your email/password. For Gmail use an App Password, not your main password.'
    except smtplib.SMTPConnectError:
        return False, f"Cannot connect to {cfg['smtp_host']}:{cfg['smtp_port']} — check host/port settings."
    except Exception as e:
        return False, str(e)

def build_alert_html(job_name, target, findings, risk_score, total_vulns):
    crit = sum(1 for f in findings if f['severity']=='critical')
    high = sum(1 for f in findings if f['severity']=='high')
    rc = '#dc2626' if risk_score<40 else '#d97706' if risk_score<70 else '#16a34a'
    rows = ''.join(f"""<tr>
      <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:11px;color:#2563eb;">{f['cve']}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">
        <span style="background:{'#fee2e2' if f['severity']=='critical' else '#fef3c7'};
        color:{'#dc2626' if f['severity']=='critical' else '#d97706'};
        padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;">{f['severity'].upper()}</span>
      </td>
      <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-size:12px;">{f['title']}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-family:monospace;font-size:11px;">{f['host']}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-weight:700;font-family:monospace;font-size:11px;">{f['cvss']}</td>
    </tr>""" for f in findings[:10])
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#f0f4f8;padding:20px;margin:0;">
<div style="max-width:680px;margin:0 auto;">
  <div style="background:linear-gradient(135deg,#1e2d45,#1a3a5c);border-radius:12px 12px 0 0;padding:24px 28px;display:flex;align-items:center;gap:14px;">
    <img src="data:image/jpeg;base64,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" alt="FalconX" style="width:50px;height:50px;object-fit:contain;border-radius:8px;flex-shrink:0;">
    <div>
      <div style="color:#fff;font-size:18px;font-weight:700;">FalconX Security Alert</div>
      <div style="color:rgba(255,255,255,.5);font-size:11px;letter-spacing:.5px;">ENTERPRISE SECURITY AUDIT SYSTEM</div>
    </div>
  </div>
  <div style="background:#fff;border:1px solid #e2e8f0;border-top:none;padding:24px 28px;">
    <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px;margin-bottom:20px;">
      <div style="color:#991b1b;font-weight:700;font-size:15px;margin-bottom:4px;">&#9888;&#65039; Critical Findings Detected</div>
      <div style="color:#991b1b;font-size:13px;">Scan <b>{job_name}</b> on target <b>{target}</b> completed with security issues requiring immediate action.</div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px;">
      <div style="text-align:center;background:#f8fafc;border-radius:8px;padding:14px;border:1px solid #e2e8f0;">
        <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600;">Risk Score</div>
        <div style="font-size:28px;font-weight:800;color:{rc};font-family:monospace;">{risk_score}<span style="font-size:14px;">/100</span></div>
      </div>
      <div style="text-align:center;background:#fef2f2;border-radius:8px;padding:14px;border:1px solid #fecaca;">
        <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600;">Critical</div>
        <div style="font-size:28px;font-weight:800;color:#dc2626;font-family:monospace;">{crit}</div>
      </div>
      <div style="text-align:center;background:#fffbeb;border-radius:8px;padding:14px;border:1px solid #fde68a;">
        <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;font-weight:600;">High</div>
        <div style="font-size:28px;font-weight:800;color:#d97706;font-family:monospace;">{high}</div>
      </div>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:20px;">
      <thead><tr style="background:#f8fafc;">
        <th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #e2e8f0;">CVE</th>
        <th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #e2e8f0;">Severity</th>
        <th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #e2e8f0;">Vulnerability</th>
        <th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #e2e8f0;">Affected Host</th>
        <th style="padding:8px 12px;text-align:left;font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #e2e8f0;">CVSS</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
    <div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:14px;font-size:12px;color:#1e40af;">
      <b>&#128274; Action Required:</b> Log in to FalconX ESAS to view full report, detailed remediation steps, and mark findings as resolved.
    </div>
  </div>
  <div style="background:#f8fafc;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 12px 12px;padding:12px 28px;font-size:11px;color:#94a3b8;text-align:center;">
    FalconX ESAS — Enterprise Security Audit System &nbsp;|&nbsp; {datetime.utcnow().strftime('%d %b %Y %H:%M UTC')}
  </div>
</div></body></html>"""

def fire_email_alerts(job_id, job_name, target, crit_findings, risk_score, total_vulns):
    def run():
        with get_db() as db:
            recs = db.execute("SELECT email FROM alert_recipients WHERE active=1").fetchall()
        to_addrs = [r['email'] for r in recs]
        if not to_addrs or not crit_findings:
            return
        subject = f"[FalconX] {len(crit_findings)} critical findings — {job_name}"
        html    = build_alert_html(job_name, target, crit_findings, risk_score, total_vulns)
        ok, err = send_alert_email(subject, html, to_addrs)
        with get_db() as db:
            for f in crit_findings[:8]:
                db.execute("INSERT INTO alerts(job_id,severity,title,message,channel,sent,error_msg) VALUES(?,?,?,?,?,?,?)",
                    (job_id, f['severity'],
                     f"{'✉ Sent' if ok else '✗ Failed'}: {f['title']}",
                     f['description'], 'email', 1 if ok else 0, '' if ok else err))
            db.commit()
    threading.Thread(target=run, daemon=True).start()

# ═══════════════════════════════════════════════════════════════════
#  SCAN RUNNER
# ═══════════════════════════════════════════════════════════════════
def run_scan(job_id):
    steps = [
        (5,  'Initializing scan engine…'),
        (12, 'Discovering live hosts…'),
        (22, 'Running port scan (SYN/TCP)…'),
        (36, 'Querying NVD / CVE database…'),
        (50, 'Fingerprinting vulnerable services…'),
        (62, 'Running compliance checks…'),
        (73, 'Checking ISO 27001 controls…'),
        (81, 'Checking NIST CSF / PCI-DSS…'),
        (90, 'Calculating risk scores…'),
        (97, 'Generating report…'),
        (100,'Scan complete'),
    ]
    def _run():
        db = get_db()
        db.execute("UPDATE scan_jobs SET status='running', started_at=? WHERE id=?",
                   (datetime.utcnow().isoformat(), job_id))
        db.commit()
        job = db.execute("SELECT * FROM scan_jobs WHERE id=?", (job_id,)).fetchone()

        for pct, step in steps:
            time.sleep(random.uniform(0.8, 1.4))
            db.execute("UPDATE scan_jobs SET progress=?, current_step=? WHERE id=?", (pct, step, job_id))
            db.commit()

        target      = job['target'] or '192.168.1.0/24'
        target_type = job['target_type'] or 'network'
        depth       = job['scan_depth'] or 'standard'
        hosts       = get_hosts_for_target(target, target_type)

        # Use job_id as seed_extra so repeated scans on same target still differ slightly
        seed_extra  = job_id
        vulns       = pick_vulns_for_target(target, target_type, depth, seed_extra)

        crit_list = []
        rng = random.Random(job_id * 7 + 13)
        for cve, title, sev, cvss, service, desc, port, cat in vulns:
            host = rng.choice(hosts)
            db.execute("""INSERT INTO scan_results
                (job_id,result_type,severity,title,description,host,service,cve_id,cvss_score,status)
                VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (job_id,'vulnerability',sev,title,desc,host,service,cve,cvss,'open'))
            if sev in ('critical','high'):
                crit_list.append({'cve':cve,'title':title,'severity':sev,'cvss':cvss,'host':host,'description':desc})

        audit_type = (job['audit_type'] or 'combined')
        if audit_type in ('compliance','combined'):
            comp_results = get_compliance_results(target, target_type, depth, seed_extra)
            for fw, fw_results in comp_results.items():
                for cid, title, desc, passed in fw_results:
                    db.execute("""INSERT INTO scan_results
                        (job_id,result_type,framework,control_id,title,description,severity,status)
                        VALUES(?,?,?,?,?,?,?,?)""",
                        (job_id,'compliance',fw,cid,title,desc,'info' if passed else 'high','pass' if passed else 'fail'))

        db.execute("UPDATE scan_jobs SET status='completed', completed_at=? WHERE id=?",
                   (datetime.utcnow().isoformat(), job_id))
        db.commit()
        db.close()

        if crit_list:
            sc = {'critical':0,'high':0}
            for f in crit_list:
                sc[f['severity']] = sc.get(f['severity'],0)+1
            risk = max(0, 100 - sc.get('critical',0)*15 - sc.get('high',0)*7)
            fire_email_alerts(job_id, job['name'] or f'Scan #{job_id}', target,
                              crit_list, risk, len(vulns))

    threading.Thread(target=_run, daemon=True).start()

# ═══════════════════════════════════════════════════════════════════
#  AUTH
# ═══════════════════════════════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get('user_id'): return redirect(url_for('login'))
        return f(*a,**k)
    return w

def api_auth(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get('user_id'): return jsonify({'error':'Not authenticated'}),401
        return f(*a,**k)
    return w

def require_role(*roles):
    def dec(f):
        @wraps(f)
        def w(*a,**k):
            if session.get('role') not in roles: return jsonify({'error':'Insufficient permissions'}),403
            return f(*a,**k)
        return w
    return dec

@app.context_processor
def inject_user():
    class U:
        is_authenticated = bool(session.get('user_id'))
        username = session.get('username','')
        role     = session.get('role','viewer')
        id       = session.get('user_id')
    return {'current_user': U()}

# ═══════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ═══════════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return redirect(url_for('dashboard') if session.get('user_id') else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        d = request.get_json() or request.form
        with get_db() as db:
            u = db.execute("SELECT * FROM users WHERE username=?",(d.get('username'),)).fetchone()
        if u and check_password_hash(u['password_hash'], d.get('password','')):
            session.update({'user_id':u['id'],'username':u['username'],'role':u['role']})
            with get_db() as db:
                db.execute("UPDATE users SET last_login=? WHERE id=?",(datetime.utcnow().isoformat(),u['id']))
            return jsonify({'ok':True,'role':u['role']})
        return jsonify({'ok':False,'error':'Invalid username or password'}),401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard(): return render_template('dashboard.html')

@app.route('/configure')
@login_required
def configure(): return render_template('configure.html')

@app.route('/reports')
@login_required
def reports(): return render_template('reports.html')

@app.route('/settings')
@login_required
def settings(): return render_template('settings.html')

@app.route('/cloud-inventory')
@login_required
def cloud_inventory(): return render_template('cloud_inventory.html')

# ═══════════════════════════════════════════════════════════════════
#  SCAN API
# ═══════════════════════════════════════════════════════════════════
@app.route('/api/scan/start', methods=['POST'])
@api_auth
@require_role('admin','auditor')
def start_scan():
    d = request.get_json()
    with get_db() as db:
        cur = db.execute("""INSERT INTO scan_jobs
            (name,audit_type,target_type,target,ports,scan_mode,scan_depth,aws_account,aws_services,created_by)
            VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (d.get('name',f"Scan {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"),
             d.get('audit_type','combined'), d.get('target_type','network'),
             d.get('target',''), d.get('ports','22,80,443,3306,3389,8080'),
             d.get('scan_mode','manual'), d.get('scan_depth','standard'),
             d.get('aws_account',''), json.dumps(d.get('aws_services',[])), session['user_id']))
        jid = cur.lastrowid
    run_scan(jid)
    return jsonify({'ok':True,'job_id':jid})

@app.route('/api/scan/<int:jid>/status')
@api_auth
def scan_status(jid):
    with get_db() as db:
        j = db.execute("SELECT * FROM scan_jobs WHERE id=?",(jid,)).fetchone()
    if not j: return jsonify({'error':'Not found'}),404
    return jsonify({'id':j['id'],'status':j['status'],'progress':j['progress'],
                    'step':j['current_step'],'started':j['started_at'],'completed':j['completed_at']})

@app.route('/api/scan/<int:jid>/results')
@api_auth
def scan_results(jid):
    with get_db() as db:
        j  = db.execute("SELECT * FROM scan_jobs WHERE id=?",(jid,)).fetchone()
        rs = db.execute("SELECT * FROM scan_results WHERE job_id=? ORDER BY id",(jid,)).fetchall()
    if not j: return jsonify({'error':'Not found'}),404
    so    = {'critical':0,'high':1,'medium':2,'low':3,'info':4}
    vulns = sorted([r for r in rs if r['result_type']=='vulnerability'], key=lambda r:so.get(r['severity'],5))
    comp  = [r for r in rs if r['result_type']=='compliance']
    scores = {}
    for fw in ('ISO27001','NIST','PCI-DSS'):
        fc = [r for r in comp if r['framework']==fw]
        if fc: scores[fw] = round(sum(1 for r in fc if r['status']=='pass')/len(fc)*100)
    sc = {'critical':0,'high':0,'medium':0,'low':0}
    for v in vulns: sc[v['severity']] = sc.get(v['severity'],0)+1
    risk = max(0, 100-min(100, sc['critical']*15+sc['high']*7+sc['medium']*3+sc['low']))
    return jsonify({
        'job':{'id':j['id'],'name':j['name'],'status':j['status'],'audit_type':j['audit_type'],
               'target':j['target'],'scan_depth':j['scan_depth'],'completed':j['completed_at']},
        'risk_score':risk,'sev_counts':sc,'compliance_scores':scores,
        'vulnerabilities':[{'id':r['id'],'cve':r['cve_id'],'title':r['title'],'severity':r['severity'],
            'cvss':r['cvss_score'],'host':r['host'],'service':r['service'],
            'description':r['description'],'status':r['status']} for r in vulns],
        'compliance':[{'id':r['id'],'framework':r['framework'],'control_id':r['control_id'],
            'title':r['title'],'description':r['description'],
            'status':r['status'],'severity':r['severity']} for r in comp],
    })

@app.route('/api/scans')
@api_auth
def list_scans():
    with get_db() as db:
        jobs = db.execute("""SELECT j.*, u.username AS started_by FROM scan_jobs j
            LEFT JOIN users u ON j.created_by=u.id ORDER BY j.id DESC LIMIT 50""").fetchall()
    return jsonify([{'id':j['id'],'name':j['name'],'status':j['status'],'audit_type':j['audit_type'],
        'target':j['target'],'progress':j['progress'],'created':j['started_at'],'completed':j['completed_at'],
        'started_by':j['started_by'] or '—'} for j in jobs])

@app.route('/api/dashboard/stats')
@api_auth
def dashboard_stats():
    with get_db() as db:
        recent = db.execute("SELECT * FROM scan_jobs WHERE status='completed' ORDER BY id DESC LIMIT 1").fetchone()
        if not recent: return jsonify({'no_scans':True})
        rs       = db.execute("SELECT * FROM scan_results WHERE job_id=?",(recent['id'],)).fetchall()
        all_jobs = db.execute("SELECT * FROM scan_jobs WHERE status='completed' ORDER BY id DESC LIMIT 7").fetchall()
        alerts   = db.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 10").fetchall()
    vulns = [r for r in rs if r['result_type']=='vulnerability']
    comp  = [r for r in rs if r['result_type']=='compliance']
    sc    = {'critical':0,'high':0,'medium':0,'low':0}
    for v in vulns: sc[v['severity']] = sc.get(v['severity'],0)+1
    risk  = max(0, 100-min(100, sc['critical']*15+sc['high']*7+sc['medium']*3+sc['low']))
    scores = {}
    for fw in ('ISO27001','NIST','PCI-DSS'):
        fc = [r for r in comp if r['framework']==fw]
        if fc: scores[fw] = round(sum(1 for r in fc if r['status']=='pass')/len(fc)*100)
    trend = []
    for j in reversed(list(all_jobs)):
        with get_db() as db2:
            cnt = db2.execute("SELECT COUNT(*) FROM scan_results WHERE job_id=? AND result_type='vulnerability'",(j['id'],)).fetchone()[0]
        trend.append({'date':(j['started_at'] or '')[:10],'count':cnt,'name':j['name'] or ''})
    return jsonify({'risk_score':risk,'sev_counts':sc,'total_vulns':len(vulns),
        'compliance_scores':scores,'trend':trend,
        'last_scan':(recent['completed_at'] or '')[:16],'last_scan_target':recent['target'] or '',
        'alerts':[{'severity':a['severity'],'title':a['title'],'sent':bool(a['sent']),'error':a['error_msg'] or ''} for a in alerts]})

# ═══════════════════════════════════════════════════════════════════
#  DEMO DATA API
# ═══════════════════════════════════════════════════════════════════
@app.route('/api/demo-targets')
@api_auth
def get_demo_targets(): return jsonify(DEMO_TARGETS)

@app.route('/api/demo-cloud')
@api_auth
def get_demo_cloud(): return jsonify(DEMO_CLOUD)

@app.route('/api/email-providers')
@api_auth
def get_email_providers(): return jsonify(EMAIL_PROVIDERS)

# ═══════════════════════════════════════════════════════════════════
#  COMPLIANCE RULES API
# ═══════════════════════════════════════════════════════════════════
@app.route('/api/rules', methods=['GET'])
@api_auth
def get_rules():
    with get_db() as db:
        rules = db.execute("SELECT * FROM compliance_rules ORDER BY framework, control_id").fetchall()
    return jsonify([{'id':r['id'],'framework':r['framework'],'control_id':r['control_id'],
        'title':r['title'],'description':r['description'],'check_type':r['check_type'],
        'check_params':r['check_params'],'severity':r['severity'],'enabled':bool(r['enabled'])} for r in rules])

@app.route('/api/rules', methods=['POST'])
@api_auth
@require_role('admin','auditor')
def create_rule():
    d = request.get_json()
    with get_db() as db:
        cur = db.execute("""INSERT INTO compliance_rules
            (framework,control_id,title,description,check_type,check_params,severity,created_by)
            VALUES(?,?,?,?,?,?,?,?)""",
            (d['framework'],d['control_id'],d['title'],d.get('description',''),
             d.get('check_type','policy'),json.dumps(d.get('check_params',{})),
             d.get('severity','medium'),session['user_id']))
    return jsonify({'ok':True,'id':cur.lastrowid})

@app.route('/api/rules/<int:rid>', methods=['PUT'])
@api_auth
@require_role('admin','auditor')
def update_rule(rid):
    d = request.get_json()
    fields = {k:v for k,v in d.items() if k in ('title','description','check_type','severity','enabled')}
    if 'check_params' in d: fields['check_params'] = json.dumps(d['check_params'])
    if fields:
        with get_db() as db:
            db.execute(f"UPDATE compliance_rules SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?",
                       list(fields.values())+[rid])
    return jsonify({'ok':True})

@app.route('/api/rules/<int:rid>', methods=['DELETE'])
@api_auth
@require_role('admin')
def delete_rule(rid):
    with get_db() as db: db.execute("DELETE FROM compliance_rules WHERE id=?",(rid,))
    return jsonify({'ok':True})

# ═══════════════════════════════════════════════════════════════════
#  USER MANAGEMENT API
# ═══════════════════════════════════════════════════════════════════
@app.route('/api/users', methods=['GET'])
@api_auth
@require_role('admin')
def get_users():
    with get_db() as db:
        users = db.execute("SELECT id,username,email,role,last_login,created_at FROM users").fetchall()
    return jsonify([dict(u) for u in users])

@app.route('/api/users', methods=['POST'])
@api_auth
@require_role('admin')
def create_user():
    d = request.get_json()
    try:
        with get_db() as db:
            db.execute("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,?)",
                       (d['username'],d['email'],generate_password_hash(d['password']),d.get('role','viewer')))
        return jsonify({'ok':True})
    except Exception as e:
        return jsonify({'error':str(e)}),400

@app.route('/api/users/<int:uid>/role', methods=['PUT'])
@api_auth
@require_role('admin')
def update_user_role(uid):
    with get_db() as db:
        db.execute("UPDATE users SET role=? WHERE id=?",(request.get_json()['role'],uid))
    return jsonify({'ok':True})

@app.route('/api/users/<int:uid>', methods=['DELETE'])
@api_auth
@require_role('admin')
def delete_user(uid):
    if uid == session['user_id']: return jsonify({'error':'Cannot delete yourself'}),400
    with get_db() as db: db.execute("DELETE FROM users WHERE id=?",(uid,))
    return jsonify({'ok':True})

# ═══════════════════════════════════════════════════════════════════
#  EMAIL CONFIG API  — simplified provider-based
# ═══════════════════════════════════════════════════════════════════
@app.route('/api/email-config', methods=['GET'])
@api_auth
@require_role('admin')
def get_email_config_api():
    cfg = get_email_cfg()
    if not cfg: return jsonify({})
    d = dict(cfg); d.pop('smtp_pass',None)
    return jsonify(d)

@app.route('/api/email-config', methods=['POST'])
@api_auth
@require_role('admin')
def save_email_config():
    d = request.get_json()
    provider = d.get('provider','gmail')
    # Auto-fill SMTP settings from provider
    pinfo = EMAIL_PROVIDERS.get(provider, EMAIL_PROVIDERS['custom'])
    smtp_host = d.get('smtp_host') or pinfo['host']
    smtp_port = int(d.get('smtp_port') or pinfo['port'])
    use_tls   = 1 if d.get('use_tls', pinfo['tls']) else 0
    with get_db() as db:
        ex = db.execute("SELECT id FROM email_config LIMIT 1").fetchone()
        if ex:
            if d.get('smtp_pass','').strip():
                db.execute("""UPDATE email_config SET provider=?,smtp_host=?,smtp_port=?,
                    smtp_user=?,smtp_pass=?,from_addr=?,use_tls=?,enabled=?,updated_at=?""",
                    (provider,smtp_host,smtp_port,d.get('smtp_user',''),d.get('smtp_pass',''),
                     d.get('from_addr',''),use_tls,1 if d.get('enabled') else 0,datetime.utcnow().isoformat()))
            else:
                db.execute("""UPDATE email_config SET provider=?,smtp_host=?,smtp_port=?,
                    smtp_user=?,from_addr=?,use_tls=?,enabled=?,updated_at=?""",
                    (provider,smtp_host,smtp_port,d.get('smtp_user',''),
                     d.get('from_addr',''),use_tls,1 if d.get('enabled') else 0,datetime.utcnow().isoformat()))
        else:
            db.execute("""INSERT INTO email_config(provider,smtp_host,smtp_port,smtp_user,smtp_pass,from_addr,use_tls,enabled)
                VALUES(?,?,?,?,?,?,?,?)""",(provider,smtp_host,smtp_port,d.get('smtp_user',''),
                 d.get('smtp_pass',''),d.get('from_addr',''),use_tls,1 if d.get('enabled') else 0))
    return jsonify({'ok':True})

@app.route('/api/email-config/test', methods=['POST'])
@api_auth
@require_role('admin')
def test_email():
    d   = request.get_json()
    to  = d.get('to','').strip()
    if not to: return jsonify({'ok':False,'error':'Enter a recipient email address first'}),400
    html = f"""<div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;">
  <div style="background:linear-gradient(135deg,#1e2d45,#1a3a5c);border-radius:10px 10px 0 0;padding:24px;text-align:center;">
    <img src="data:image/jpeg;base64,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" alt="FalconX" style="width:64px;height:64px;object-fit:contain;margin:0 auto 10px;display:block;">
    <div style="color:#fff;font-size:17px;font-weight:700;">FalconX ESAS — Email Test</div>
  </div>
  <div style="background:#fff;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 10px 10px;padding:28px;text-align:center;">
    <div style="font-size:48px;margin-bottom:14px;">&#9989;</div>
    <h2 style="color:#1e2d45;margin-bottom:8px;">Email Alerts Working!</h2>
    <p style="color:#64748b;font-size:14px;line-height:1.6;">Your SMTP settings are configured correctly.<br>
    Security alerts will be sent automatically after any scan that detects critical or high severity vulnerabilities.</p>
    <p style="color:#94a3b8;font-size:11px;margin-top:20px;">Sent: {datetime.utcnow().strftime('%d %b %Y %H:%M UTC')}</p>
  </div>
</div>"""
    ok, err = send_alert_email("FalconX ESAS — Email Test ✅", html, [to])
    return jsonify({'ok':ok, 'error': err if not ok else None})

@app.route('/api/alert-recipients', methods=['GET'])
@api_auth
@require_role('admin')
def get_recipients():
    with get_db() as db:
        rows = db.execute("SELECT * FROM alert_recipients ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/alert-recipients', methods=['POST'])
@api_auth
@require_role('admin')
def add_recipient():
    d = request.get_json()
    try:
        with get_db() as db:
            db.execute("INSERT INTO alert_recipients(email,severity_filter,active) VALUES(?,?,1)",
                       (d['email'], d.get('severity_filter','critical,high')))
        return jsonify({'ok':True})
    except Exception as e:
        return jsonify({'error':str(e)}),400

@app.route('/api/alert-recipients/<int:rid>', methods=['DELETE'])
@api_auth
@require_role('admin')
def delete_recipient(rid):
    with get_db() as db: db.execute("DELETE FROM alert_recipients WHERE id=?",(rid,))
    return jsonify({'ok':True})

# ═══════════════════════════════════════════════════════════════════
#  MISC API
# ═══════════════════════════════════════════════════════════════════
@app.route('/api/topology')
@api_auth
def topology():
    return jsonify({'nodes':[
        {'id':'fw',  'label':'Firewall',      'type':'firewall',   'ip':'10.0.0.1',      'status':'secure'},
        {'id':'sw1', 'label':'Core Switch',   'type':'switch',     'ip':'10.0.0.2',      'status':'secure'},
        {'id':'sw2', 'label':'Access Switch', 'type':'switch',     'ip':'10.0.0.3',      'status':'secure'},
        {'id':'app1','label':'APP-SRV-01',    'type':'server',     'ip':'192.168.1.10',  'status':'vulnerable'},
        {'id':'app2','label':'APP-SRV-02',    'type':'server',     'ip':'192.168.1.11',  'status':'secure'},
        {'id':'db1', 'label':'DB-SRV-04',     'type':'database',   'ip':'192.168.1.44',  'status':'critical'},
        {'id':'ci1', 'label':'CI-Jenkins',    'type':'server',     'ip':'192.168.1.60',  'status':'warning'},
        {'id':'ws1', 'label':'WS-112',        'type':'workstation','ip':'192.168.1.112', 'status':'warning'},
        {'id':'cld', 'label':'AWS Cloud',     'type':'cloud',      'ip':'54.92.148.200', 'status':'secure'},
    ],'edges':[
        {'from':'fw','to':'sw1'},{'from':'sw1','to':'sw2'},
        {'from':'sw1','to':'app1'},{'from':'sw1','to':'app2'},
        {'from':'sw1','to':'db1'},{'from':'sw2','to':'ci1'},
        {'from':'sw2','to':'ws1'},{'from':'fw','to':'cld'},
    ]})

@app.route('/api/remediation/<cve_id>')
@api_auth
def get_remediation(cve_id):
    return jsonify({'guidance': REMEDIATION.get(cve_id,
        f'Review the official vendor advisory for {cve_id}. Apply the latest available patches and validate in a staging environment before deploying to production.')})

@app.route('/api/result/<int:rid>/fix', methods=['POST'])
@api_auth
@require_role('admin','auditor')
def mark_fixed(rid):
    with get_db() as db: db.execute("UPDATE scan_results SET status='fixed' WHERE id=?",(rid,))
    return jsonify({'ok':True})

@app.route('/api/report/<int:jid>/pdf')
@api_auth
def export_pdf(jid):
    with get_db() as db:
        j  = db.execute("SELECT j.*,u.username as started_by FROM scan_jobs j LEFT JOIN users u ON j.created_by=u.id WHERE j.id=?",(jid,)).fetchone()
        rs = db.execute("SELECT * FROM scan_results WHERE job_id=?",(jid,)).fetchall()
    vulns = sorted([r for r in rs if r['result_type']=='vulnerability'],key=lambda x:{'critical':0,'high':1,'medium':2,'low':3}.get(x['severity'],4))
    comp  = [r for r in rs if r['result_type']=='compliance']
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_CENTER
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf,pagesize=A4,leftMargin=2*cm,rightMargin=2*cm,topMargin=2*cm,bottomMargin=2*cm)
        styles = getSampleStyleSheet(); story=[]
        TS = ParagraphStyle('T',fontSize=20,fontName='Helvetica-Bold',spaceAfter=4,alignment=TA_CENTER,textColor=colors.HexColor('#1e2d45'))
        H2 = ParagraphStyle('H',fontSize=13,fontName='Helvetica-Bold',spaceAfter=4,textColor=colors.HexColor('#1a3a5c'))
        SM = ParagraphStyle('S',fontSize=9,spaceAfter=3,textColor=colors.HexColor('#64748b'))
        sc = {'critical':0,'high':0,'medium':0,'low':0}
        for v in vulns: sc[v['severity']] = sc.get(v['severity'],0)+1
        risk = max(0,100-min(100,sc['critical']*15+sc['high']*7+sc['medium']*3+sc['low']))
        buf_logo = io.BytesIO(__import__('base64').b64decode('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'))
        from reportlab.platypus import Image as RLImage
        try:
            logo_img = RLImage(buf_logo, width=1.5*cm, height=1.5*cm)
            from reportlab.platypus import HRFlowable as HRF
            story.append(logo_img)
        except: pass
        story.append(Paragraph('FalconX — Enterprise Security Audit Report', TS))
        story.append(Paragraph(f"Scan: {j['name']} | By: {j['started_by'] or 'N/A'} | Target: {j['target'] or 'N/A'} | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",SM))
        story.append(Spacer(1,0.3*cm))
        story.append(HRFlowable(width='100%',thickness=2,color=colors.HexColor('#1a3a5c')))
        story.append(Spacer(1,0.3*cm))
        story.append(Paragraph('Executive Summary',H2))
        sd=[['Metric','Value'],['Risk Score (100=clean)',f"{risk}/100"],
            ['Total Vulnerabilities',str(len(vulns))],['Critical',str(sc['critical'])],
            ['High',str(sc['high'])],['Medium',str(sc['medium'])],['Low',str(sc['low'])],
            ['Audit Type',str(j['audit_type'] or '').title()],['Target',str(j['target'] or 'N/A')],
            ['Scan Depth',str(j['scan_depth'] or '').title()],['Completed',str((j['completed_at'] or '')[:16])]]
        t=Table(sd,colWidths=[9*cm,8*cm])
        t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1a3a5c')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
            ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#f0f4f8'),colors.white]),
            ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#cccccc')),('FONTSIZE',(0,0),(-1,-1),10),('PADDING',(0,0),(-1,-1),6)]))
        story.append(t); story.append(Spacer(1,0.4*cm))
        if vulns:
            story.append(Paragraph(f'Vulnerability Findings ({len(vulns)} total)',H2))
            vc={'critical':colors.HexColor('#fee2e2'),'high':colors.HexColor('#fef3c7'),'medium':colors.HexColor('#dbeafe'),'low':colors.HexColor('#d1fae5')}
            vd=[['CVE ID','Severity','CVSS','Host/Target','Service/Port']]
            for v in vulns:
                vd.append([v['cve_id'] or 'N/A',v['severity'].upper(),str(v['cvss_score'] or '—'),v['host'] or '—',v['service'] or '—'])
            vt=Table(vd,colWidths=[3.5*cm,2.5*cm,1.8*cm,5.2*cm,4*cm])
            vts=[('BACKGROUND',(0,0),(-1,0),colors.HexColor('#374151')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
                ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#e5e7eb')),
                ('FONTSIZE',(0,0),(-1,-1),9),('PADDING',(0,0),(-1,-1),5)]
            for i,row in enumerate(vd[1:],1):
                vts.append(('BACKGROUND',(0,i),(-1,i),vc.get(row[1].lower(),colors.white)))
            vt.setStyle(TableStyle(vts)); story.append(vt); story.append(Spacer(1,0.4*cm))
        for fw in ('ISO27001','NIST','PCI-DSS'):
            fc=[r for r in comp if r['framework']==fw]
            if not fc: continue
            passed=sum(1 for r in fc if r['status']=='pass')
            story.append(Paragraph(f"{fw} Compliance — {round(passed/len(fc)*100)}% ({passed}/{len(fc)} controls passed)",H2))
            cd=[['Control','Title','Result']]+[[c['control_id'],c['title'],'PASS' if c['status']=='pass' else 'FAIL'] for c in fc]
            ct=Table(cd,colWidths=[2.5*cm,13.5*cm,2.5*cm])
            cts=[('BACKGROUND',(0,0),(-1,0),colors.HexColor('#374151')),('TEXTCOLOR',(0,0),(-1,0),colors.white),
                ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#e5e7eb')),
                ('FONTSIZE',(0,0),(-1,-1),8),('PADDING',(0,0),(-1,-1),4)]
            for i,row in enumerate(cd[1:],1):
                cts.append(('BACKGROUND',(2,i),(2,i),colors.HexColor('#d1fae5') if row[2]=='PASS' else colors.HexColor('#fee2e2')))
            ct.setStyle(TableStyle(cts)); story.append(ct); story.append(Spacer(1,0.3*cm))
        story.append(Spacer(1,0.2*cm))
        story.append(HRFlowable(width='100%',thickness=0.5,color=colors.HexColor('#e2e8f0')))
        story.append(Paragraph(f"Generated by FalconX ESAS — {datetime.utcnow().strftime('%d %b %Y %H:%M UTC')}",SM))
        doc.build(story); buf.seek(0)
        fname=f"ESAS_{(j['name'] or 'Report').replace(' ','_')}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
        return send_file(buf,mimetype='application/pdf',download_name=fname,as_attachment=True)
    except ImportError:
        lines=[f"ESAS REPORT: {j['name']}\nTarget: {j['target']}\nGenerated: {datetime.utcnow().isoformat()}\n\n"]
        for v in vulns: lines.append(f"[{v['severity'].upper()}] {v['cve_id']} — {v['title']} | Host: {v['host']}\n")
        return send_file(io.BytesIO(''.join(lines).encode()),mimetype='text/plain',download_name=f'ESAS_{jid}.txt',as_attachment=True)

# ═══════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    init_db()
    print("\n🔐 FalconX ESAS  →  http://localhost:5000")
    print("   admin / Admin@123  |  auditor / Audit@123  |  viewer / View@123")
    print("   5 demo scans pre-loaded with unique results per target\n")
    app.run(debug=True, port=5000)

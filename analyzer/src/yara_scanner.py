#!/usr/bin/env python3
"""
Standalone YARA scanner for PackageInferno.

This runs as a separate worker that:
1. Pulls from the SQS analyze queue (same as analyzer)
2. Downloads tarballs from S3
3. Runs YARA rules on all files
4. Creates separate .yara.findings.json file
5. Uploads findings to S3
6. Inserts findings into database

This allows YARA to run at scale without blocking the main analyzer.
"""

import json
import os
import sys
import tarfile
import tempfile
import time
import yaml
from pathlib import Path
from typing import Optional

# YARA
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("yara-python not installed, YARA scanning disabled")

# AWS
import boto3

# Database
import psycopg2
from psycopg2.extras import Json

def get_aws_secret(secret_name: str, region: str = 'us-east-2') -> dict:
    """Get secret from AWS Secrets Manager."""
    client = boto3.client('secretsmanager', region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response['SecretString'])

def get_db_conn():
    """Get database connection using IAM auth."""
    secret_name = os.getenv('DB_SECRET_NAME', 'package-inferno/aurora/postgres')
    db_name = os.getenv('DB_NAME', 'packageinferno')
    region = os.getenv('AWS_REGION', 'us-east-2')
    
    try:
        secret = get_aws_secret(secret_name, region)
        host = secret.get('host', 'package-inferno-cluster.cluster-cbocqwhrijxc.us-east-2.rds.amazonaws.com')
        user = secret.get('username', 'pi_admin')
        password = secret.get('password')
        
        conn = psycopg2.connect(
            host=host,
            port=5432,
            database=db_name,
            user=user,
            password=password
        )
        return conn
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None

def load_yara_rules(rules_path: str = 'yara-rules/packages/full/yara-rules-full.yar'):
    """Load and compile YARA rules."""
    if not YARA_AVAILABLE:
        return None
    
    search_paths = [
        Path(rules_path),
        Path(__file__).parent.parent / rules_path,
        Path('/app') / rules_path
    ]
    
    rules_file = None
    for p in search_paths:
        if p.exists():
            rules_file = p
            break
    
    if not rules_file:
        print(f"YARA rules not found at {rules_path}")
        return None
    
    try:
        print(f"Loading YARA rules from {rules_file}...")
        compiled_rules = yara.compile(filepath=str(rules_file))
        print(f"YARA rules loaded successfully")
        return compiled_rules
    except Exception as e:
        print(f"Failed to load YARA rules: {e}")
        return None

def determine_severity(match) -> str:
    """Determine severity from YARA match tags."""
    tags = {tag.lower() for tag in match.tags}
    
    # High severity indicators
    high_tags = {'malware', 'exploit', 'backdoor', 'trojan', 'ransomware', 'apt', 'rat', 'rootkit'}
    if any(tag in high_tags for tag in tags):
        return 'high'
    
    # Medium severity indicators  
    medium_tags = {'suspicious', 'pua', 'webshell', 'cryptominer', 'dropper', 'downloader', 'stealer'}
    if any(tag in medium_tags for tag in tags):
        return 'medium'
    
    return 'low'

def scan_file_with_yara(file_path: Path, yara_rules, max_size_mb: int = 999999, timeout: int = 300):
    """Scan a single file with YARA."""
    findings = []
    
    try:
        file_size = file_path.stat().st_size
        max_size = max_size_mb * 1024 * 1024
        
        if file_size > max_size:
            return findings
        
        matches = yara_rules.match(str(file_path), timeout=timeout)
        
        for match in matches:
            severity = determine_severity(match)
            
            # Extract metadata
            metadata = {}
            for key, val in match.meta.items():
                try:
                    metadata[key] = str(val) if val is not None else ''
                except:
                    metadata[key] = ''
            
            # Get matched strings
            matched_strings = []
            for string_match in match.strings:
                try:
                    string_identifier = string_match[1]
                    matched_data = string_match[2]
                    
                    if isinstance(matched_data, bytes):
                        try:
                            matched_data = matched_data.decode('utf-8', errors='ignore')
                        except:
                            matched_data = matched_data.hex()
                    
                    matched_strings.append({
                        'identifier': string_identifier,
                        'data': matched_data[:200]  # Limit to 200 chars
                    })
                except:
                    continue
            
            description = metadata.get('description', '')
            pattern_type = 'malicious' if severity == 'high' else 'suspicious'
            
            finding = {
                'rule': 'yara_match',
                'severity': severity,
                'details': {
                    'path': str(file_path),
                    'file_name': file_path.name,
                    'file_size_bytes': file_size,
                    'yara_rule': match.rule,
                    'yara_namespace': match.namespace,
                    'yara_tags': list(match.tags),
                    'yara_metadata': metadata,
                    'matched_strings': matched_strings,
                    'match_count': len(match.strings),
                    'explanation': f'YARA rule "{match.rule}" triggered on {file_path.name}. Pattern type: {pattern_type}. {description}'
                }
            }
            
            findings.append(finding)
    
    except Exception as e:
        # Silently skip files that error (likely binary incompatibilities)
        pass
    
    return findings

def scan_package(tarball_path: Path, yara_rules, max_size_mb: int = 999999, timeout: int = 300):
    """Extract and scan all files in a package with YARA."""
    findings = []
    
    with tempfile.TemporaryDirectory(prefix='yara-scan-') as tmpdir:
        try:
            # Extract tarball
            with tarfile.open(tarball_path, 'r:gz') as tar:
                tar.extractall(tmpdir, filter='data')
            
            # Scan all files
            for file_path in Path(tmpdir).rglob('*'):
                if file_path.is_file():
                    findings.extend(scan_file_with_yara(file_path, yara_rules, max_size_mb, timeout))
        
        except Exception as e:
            print(f"Error scanning {tarball_path.name}: {e}")
    
    return findings

def upload_to_s3(local_path: Path, s3_bucket: str, s3_key: str):
    """Upload findings file to S3."""
    try:
        s3 = boto3.client('s3', region_name=os.getenv('AWS_REGION', 'us-east-2'))
        s3.upload_file(str(local_path), s3_bucket, s3_key)
        return True
    except Exception as e:
        print(f"S3 upload failed: {e}")
        return False

def insert_findings_to_db(conn, package_name: str, version: str, findings: list):
    """Insert YARA findings into database."""
    if not conn or not findings:
        return
    
    try:
        cur = conn.cursor()
        
        # Get version_id
        cur.execute("""
            SELECT v.id FROM versions v
            JOIN packages p ON p.id = v.package_id
            WHERE p.name = %s AND v.version = %s
        """, (package_name, version))
        
        row = cur.fetchone()
        if not row:
            print(f"Version not found in DB: {package_name}@{version}")
            return
        
        version_id = row[0]
        
        # Insert findings
        for finding in findings:
            try:
                cur.execute("""
                    INSERT INTO findings (version_id, rule, severity, details)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (
                    version_id,
                    finding.get('rule'),
                    finding.get('severity'),
                    Json(finding.get('details', {}))
                ))
            except Exception as e:
                print(f"Failed to insert finding: {e}")
                continue
        
        conn.commit()
        print(f"Inserted {len(findings)} YARA findings for {package_name}@{version}")
    
    except Exception as e:
        print(f"Database insert failed: {e}")
        conn.rollback()

def process_message(msg: dict, yara_rules, s3_tarballs: str, s3_findings: str, conn, max_file_size_mb: int, timeout_seconds: int):
    """Process a single SQS message."""
    try:
        body = json.loads(msg['Body'])
        package_name = body.get('name')
        version = body.get('version')
        
        if not package_name or not version:
            print(f"Invalid message: {body}")
            return False
        
        print(f"Scanning {package_name}@{version} with YARA...")
        
        # Download tarball from S3
        tarball_name = f"{package_name}-{version}.tgz"
        s3_key = f"npm-raw-tarballs/{package_name}/{version}.tgz"
        
        with tempfile.TemporaryDirectory() as tmpdir:
            local_tarball = Path(tmpdir) / tarball_name
            
            s3 = boto3.client('s3', region_name=os.getenv('AWS_REGION', 'us-east-2'))
            
            try:
                s3.download_file(s3_tarballs, s3_key, str(local_tarball))
            except Exception as e:
                print(f"Failed to download {s3_key}: {e}")
                return False
            
            # Scan with YARA
            findings = scan_package(local_tarball, yara_rules, max_file_size_mb, timeout_seconds)
            
            if not findings:
                print(f"  No YARA matches for {package_name}@{version}")
                return True  # Success, just no matches
            
            print(f"  Found {len(findings)} YARA matches!")
            
            # Create findings file
            findings_data = {
                'package': {'name': package_name, 'version': version},
                'scanner': 'yara',
                'findings': findings,
                'scan_time': time.time()
            }
            
            # Save locally
            safe_name = package_name.replace('/', '__').replace('@', '')
            findings_filename = f"{safe_name}@{version}.yara.findings.json"
            findings_path = Path(tmpdir) / findings_filename
            findings_path.write_text(json.dumps(findings_data, indent=2))
            
            # Upload to S3
            s3_findings_key = f"npm-findings/{safe_name}@{version}.yara.findings.json"
            if upload_to_s3(findings_path, s3_findings, s3_findings_key):
                print(f"  Uploaded YARA findings to S3")
            
            # Insert into database
            insert_findings_to_db(conn, package_name, version, findings)
        
        return True
    
    except Exception as e:
        print(f"Error processing message: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main YARA scanner loop."""
    print("=" * 60)
    print("PackageInferno YARA Scanner")
    print("=" * 60)
    print("")
    
    # Load config
    config_path = Path(__file__).parent.parent / 'scan.yml'
    if not config_path.exists():
        config_path = Path('../scan.yml')
    
    if config_path.exists():
        with open(config_path) as f:
            cfg = yaml.safe_load(f)
        
        if cfg:
            yara_cfg = cfg.get('analysis', {}).get('yara', {})
        else:
            cfg = {}
            yara_cfg = {}
    else:
        cfg = {}
        yara_cfg = {}
    
    if not yara_cfg:
        print("Warning: YARA config not found in scan.yml, using defaults")
        yara_cfg = {
            'enabled': True,
            'rules_path': 'yara-rules/packages/full/yara-rules-full.yar',
            'max_file_size_mb': 999999,
            'timeout_seconds': 300
        }
    
    max_file_size_mb = int(yara_cfg.get('max_file_size_mb', 999999) or 999999)
    timeout_seconds = int(yara_cfg.get('timeout_seconds', 300) or 300)

    # Load YARA rules
    yara_rules = load_yara_rules(yara_cfg.get('rules_path'))
    if not yara_rules:
        print("Failed to load YARA rules, exiting")
        sys.exit(1)
    
    # Get database connection
    conn = get_db_conn()
    if not conn:
        print("Warning: Database connection failed, will skip DB inserts")
    
    # AWS/SQS setup
    region = os.getenv('AWS_REGION', 'us-east-2')
    queue_url = os.getenv('SQS_ANALYZE_URL')
    s3_tarballs = os.getenv('S3_TARBALLS', 'package-inferno-tarballs')
    s3_findings = os.getenv('S3_FINDINGS', 'package-inferno-findings')
    
    if not queue_url:
        print("SQS_ANALYZE_URL not set, exiting")
        sys.exit(1)
    
    sqs = boto3.client('sqs', region_name=region)
    
    print(f"Listening on: {queue_url}")
    print(f"S3 Tarballs: {s3_tarballs}")
    print(f"S3 Findings: {s3_findings}")
    print("")
    
    # Main loop
    while True:
        try:
            response = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20,
                VisibilityTimeout=300
            )
            
            messages = response.get('Messages', [])
            if not messages:
                continue
            
            for msg in messages:
                success = process_message(msg, yara_rules, s3_tarballs, s3_findings, conn, max_file_size_mb, timeout_seconds)
                
                if success:
                    # Delete message from queue
                    sqs.delete_message(
                        QueueUrl=queue_url,
                        ReceiptHandle=msg['ReceiptHandle']
                    )
        
        except KeyboardInterrupt:
            print("\nShutting down...")
            break
        except Exception as e:
            print(f"Error in main loop: {e}")
            time.sleep(5)

if __name__ == '__main__':
    main()


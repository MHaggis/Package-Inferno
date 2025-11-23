# analyzer/src/analyzer.py
# Python 3.10+
# PackageInferno: enhanced static analyzer for npm tarballs
import os, sys, tarfile, json, re, shutil, tempfile, base64, math, time, traceback
from bisect import bisect_right
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import yaml
import psycopg2
from psycopg2.extras import Json
import boto3

# YARA support (optional - graceful degradation if not available)
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("Warning: yara-python not installed. YARA scanning disabled.")

# ---------------------------
# Typosquat Detection - Popular Packages
# ---------------------------
POPULAR_PACKAGES = {
    # Core packages
    'lodash', 'express', 'react', 'vue', 'angular', 'typescript',
    'webpack', 'babel', 'eslint', 'prettier', 'axios', 'moment',
    'jquery', 'bootstrap', 'commander', 'chalk', 'debug', 'fs-extra',
    'next', 'nuxt', 'svelte', 'vite', 'rollup', 'esbuild',
    
    # Scoped packages  
    '@angular/core', '@angular/common', '@babel/core', '@types/node',
    '@typescript-eslint/parser', '@vue/cli', '@nuxt/core',
    
    # Security/crypto related
    'bcrypt', 'jsonwebtoken', 'passport', 'crypto-js', 'uuid',
    
    # AI/ML related (high value targets)
    '@anthropic-ai/sdk', '@anthropic-ai/claude-code', '@openai/api', 'openai',
    '@huggingface/transformers', 'tensorflow', 'pytorch',
    
    # Popular CLIs
    'create-react-app', 'create-vue', '@vue/cli', '@angular/cli',
    'serverless', 'aws-cli', 'firebase-tools'
}

# Character substitutions for typosquat detection
TYPOSQUAT_SUBSTITUTIONS = {
    'o': ['0', 'ο', 'о'],  # Latin o, digit 0, Greek omicron, Cyrillic o
    'a': ['а', 'α'],       # Latin a, Cyrillic a, Greek alpha
    'e': ['е', 'ε', '3'],  # Latin e, Cyrillic e, Greek epsilon
    'i': ['і', 'ι', 'l', '1'],  # Latin i, Cyrillic i, Greek iota, l, 1
    'l': ['ӏ', '1', 'i'],  # Cyrillic l, digit 1, i
    's': ['ѕ', '$', '5'],  # Cyrillic s, dollar, 5
}

# ---------------------------
# Environment / Config
# ---------------------------
DOWNLOADS_DIR = os.environ.get('DOWNLOADS_DIR', './downloads')
FINDINGS_DIR = os.environ.get('FINDINGS_DIR', './out/findings')
MAX_BYTES = int(os.environ.get('MAX_EXTRACT_BYTES', '0'))
AWS_REGION = os.environ.get('AWS_REGION', 'us-west-2')

DB_URL = os.environ.get('DB_URL')
DB_SECRET_NAME = os.environ.get('DB_SECRET_NAME')
DB_ENDPOINT = os.environ.get('DB_ENDPOINT')
DB_NAME = os.environ.get('DB_NAME', 'packageinferno')

SQS_ANALYZE_URL = os.environ.get('SQS_ANALYZE_URL')
S3_TARBALLS = os.environ.get('S3_TARBALLS')

LOCAL_ONLY = os.environ.get('LOCAL_ONLY', 'true') == 'true'
QUEUE_MODE = os.environ.get('QUEUE_MODE', 'file' if LOCAL_ONLY or not SQS_ANALYZE_URL else 'sqs')

SCAN_YML_PATH = os.environ.get('SCAN_YML', str(Path(__file__).resolve().parents[2] / 'scan.yml'))

os.makedirs(FINDINGS_DIR, exist_ok=True)

# ---------------------------
# Heuristics / Patterns
# ---------------------------

# Lifecycle hooks we care about
LIFECYCLE_KEYS = [
    'preinstall','install','postinstall','prepare',
    'prepublish','prepublishOnly','postpublish'
]

# Build-ish commands that are often benign (downgrade unless they combine with risky stuff)
DEFAULT_BENIGN_BUILD_TOOLS = [
    r'\bnode-gyp\b', r'\btsc\b', r'\besbuild\b', r'\brollup\b', r'\bwebpack\b',
    r'\bhusky\s+install\b', r'\bnpm\s+run\s+build\b', r'\bpnpm\s+build\b', r'\byarn\s+build\b'
]

# Shell spawns & downloaders
SHELL_RE = re.compile(r'\b(sh|bash|zsh|cmd(\.exe)?|powershell|pwsh)\b', re.I)
DOWNLOADER_RE = re.compile(
    r'\b(curl|wget|bitsadmin|certutil|Invoke-WebRequest|iwr|Start-BitsTransfer)\b', re.I
)

# Node child_process usage
NODE_SHELL_API_RE = re.compile(r'\bchild_process\s*\.\s*(exec|spawn|execSync|execFile)\b', re.I)

# Network libraries in JS
NET_CLIENT_RE = re.compile(rb'(https?\.get|http\.request|undici|axios\s*\(|node[-_]fetch\s*\()', re.I)

# C2 / exfil destinations
C2_RE = re.compile(rb'(discord(app)?\.com/api|hooks\.slack\.com|api\.telegram\.org|pastebin\.com|webhook(site)?|ipfs://|ngrok\.io|oast\.)', re.I)

# FS writes (we’ll later attempt to classify destination path)
FS_WRITE_RE = re.compile(rb'fs\.(writeFile|appendFile|createWriteStream|copyFile|mkdir)\s*\(', re.I)

# CI-evasion
CI_EVASION_RE = re.compile(rb'process\.env\.CI|is-docker|is-wsl', re.I)

# process.env exfil keys
ENV_KEYS_RE = re.compile(
    r'process\.env\.(AWS_[A-Z0-9_]+|GITHUB_[A-Z0-9_]+|NPM_TOKEN|NODE_AUTH_TOKEN|DOCKER[A-Z0-9_]*|AZURE[A-Z0-9_]*|GOOGLE[A-Z0-9_]*|SECRET|TOKEN|KEY|PASSWORD)',
    re.I
)

# Generic suspicious patterns you already had (kept)
GENERIC_SUSPICIOUS_PATTERNS = [
    re.compile(rb'child_process\s*\.\s*(exec|spawn|execSync|execFile)', re.I),
    re.compile(rb'\beval\s*\(|new\s+Function\s*\(', re.I),
    re.compile(rb'https?://[^\s\'"]+', re.I),
    re.compile(rb'process\.env\.[A-Z0-9_]+', re.I),
]

# Webpack / Minified indicators
WEBPACK_BOOTSTRAP_RE = re.compile(rb'__webpack_require__|webpackJsonp|/\*! For license information please see', re.I)
VERY_LONG_LINE_RE = re.compile(rb'.{4000,}')

# File magic
WASM_MAGIC = b'\x00asm'
PE_MAGIC = b'MZ'
ELF_MAGIC = b'\x7fELF'
MACHO_MAGICS = [b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe']

# URLs
URL_RE = re.compile(rb'https?://[^\s\'"]+', re.I)

# Big JS / entropy thresholds (can be overridden via env)
BIG_JS_BYTES = int(os.environ.get('BIG_JS_BYTES', str(1_000_000)))   # 1MB
HIGH_ENTROPY = float(os.environ.get('HIGH_ENTROPY', '7.2'))          # ~binary/packed

# Paths that indicate writing outside package / sensitive areas
OUTSIDE_PATH_HINT_RE = re.compile(
    rb'(\.npmrc|\.ssh|/etc/|~\/|%APPDATA%|%USERPROFILE%|C:\\\\Users\\\\|/home/[^/]+/|/usr/local/bin|/usr/bin|\.bashrc|\.zshrc|\.profile|PowerShell\\Microsoft\.PowerShell_profile\.ps1)',
    re.I
)

# node-pre-gyp / prebuild-install (native module fetchers)
PREBUILD_RE = re.compile(rb'(prebuild-install|node-pre-gyp)', re.I)

# shrinkwrap/lock presence
LOCKFILES = {'npm-shrinkwrap.json','package-lock.json'}

# Phishing & credential capture patterns (from ClickGrab)
PASSWORD_INPUT_RE = re.compile(rb'<input[^>]*(type=["\']password["\']|password)', re.I)
CREDENTIAL_FORM_RE = re.compile(rb'<input[^>]*(name=["\']?(username|email|login|user|pass|password))', re.I)
FORM_ACTION_RE = re.compile(rb'<form[^>]*action=["\']([^"\']+)', re.I)
IFRAME_RE = re.compile(rb'<iframe[^>]*src=["\']([^"\']+)', re.I)

# Fake CAPTCHA / ClickFix patterns
FAKE_CAPTCHA_RE = re.compile(rb'(verify you are human|not a robot|captcha|cloudflare|turnstile)', re.I)
SUSPICIOUS_BUTTON_RE = re.compile(rb'<button[^>]*>(verify|continue|i\'m not a robot|allow|enable|fix)', re.I)

# CDN loading patterns
CDN_LOAD_RE = re.compile(rb'(unpkg\.com|jsdelivr\.net|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|esm\.sh|cdn\.skypack\.dev)', re.I)
SCRIPT_SRC_RE = re.compile(rb'<script[^>]*src=["\']([^"\']+)', re.I)
LINK_HREF_RE = re.compile(rb'<link[^>]*href=["\']([^"\']+)', re.I)

# Python web server patterns
PYTHON_SERVER_RE = re.compile(rb'(from flask import|from fastapi import|http\.server|SimpleHTTPServer|HTTPServer|socketserver)', re.I)
PYTHON_DOWNLOAD_RE = re.compile(rb'(requests\.(get|post)|urllib\.request|wget|curl)', re.I)
PYTHON_SOCKET_RE = re.compile(rb'(socket\.socket|bind\(|listen\(|accept\()', re.I)

# Shell/Script suspicious patterns
SCRIPT_DOWNLOAD_RE = re.compile(rb'(curl|wget|bitsadmin|certutil|Invoke-WebRequest|iwr)\s+.*https?://', re.I)

# ---------------------------
# Helpers
# ---------------------------
def shannon_entropy(bs: bytes, sample=4096):
    if not bs:
        return 0.0
    data = bs[:sample] if len(bs) > sample else bs
    from collections import Counter
    counts = Counter(data)
    probs = [c/len(data) for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate edit distance between two strings for typosquat detection."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def extract_package_name(package: str) -> str:
    """Extract package name without scope."""
    if package.startswith('@'):
        parts = package.split('/')
        return parts[1] if len(parts) > 1 else package[1:]
    return package

def detect_typosquat(package_name: str) -> dict:
    """Detect if package name is typosquatting a popular package."""
    pkg_name = extract_package_name(package_name)
    
    for popular in POPULAR_PACKAGES:
        pop_name = extract_package_name(popular)
        
        # Skip if identical
        if pkg_name == pop_name or package_name == popular:
            continue
        
        # Check Levenshtein distance
        distance = levenshtein_distance(pkg_name.lower(), pop_name.lower())
        
        # Thresholds based on name length
        threshold = 3 if len(pop_name) > 6 else (2 if len(pop_name) >= 4 else 1)
        
        if distance <= threshold:
            similarity = (1 - distance / max(len(pkg_name), len(pop_name))) * 100
            typo_type = 'edit_distance'
            
            if len(pkg_name) == len(pop_name) - 1:
                typo_type = 'character_omission'
            elif len(pkg_name) == len(pop_name) + 1:
                typo_type = 'character_insertion'
            elif len(pkg_name) == len(pop_name):
                typo_type = 'character_substitution'
            
            return {
                'is_typosquat': True,
                'target_package': popular,
                'similarity': round(similarity, 1),
                'edit_distance': distance,
                'typosquat_type': typo_type
            }
        
        # Check character substitution attacks
        if len(pkg_name) == len(pop_name):
            substitution_count = 0
            for s_char, p_char in zip(pkg_name.lower(), pop_name.lower()):
                if s_char != p_char:
                    if p_char in TYPOSQUAT_SUBSTITUTIONS:
                        if s_char in TYPOSQUAT_SUBSTITUTIONS[p_char]:
                            substitution_count += 1
            
            if substitution_count > 0 and substitution_count <= 2:
                return {
                    'is_typosquat': True,
                    'target_package': popular,
                    'similarity': 95.0,
                    'edit_distance': substitution_count,
                    'typosquat_type': 'unicode_substitution'
                }
        
        # Check scope hijacking
        if package_name.startswith('@') and popular.startswith('@'):
            pkg_scope = package_name.split('/')[0]
            pop_scope = popular.split('/')[0]
            if pkg_scope != pop_scope and pkg_name == pop_name:
                return {
                    'is_typosquat': True,
                    'target_package': popular,
                    'similarity': 100.0,
                    'edit_distance': 0,
                    'typosquat_type': 'scope_hijacking'
                }
    
    return {'is_typosquat': False}

def analyze_obfuscation(content: bytes) -> dict:
    """Enhanced obfuscation detection with technique identification."""
    techniques = []
    details = {}
    
    try:
        text = content.decode('utf-8', 'ignore')
    except:
        return {'techniques': [], 'confidence': 'low'}
    
    # Hex encoding (x61 x70 x69)
    hex_pattern = r'\\?x[0-9a-fA-F]{2}(?:\s*\\?x[0-9a-fA-F]{2})+'
    hex_matches = re.findall(hex_pattern, text)
    if hex_matches:
        techniques.append('hex_encoding')
        try:
            sample = hex_matches[0].replace('\\x', '').replace('x', '').replace(' ', '')
            decoded = bytes.fromhex(sample[:100]).decode('ascii', errors='ignore')
            details['hex_decoded_sample'] = decoded[:50]
        except:
            pass
    
    # XOR encryption
    if re.search(r'(String\.fromCharCode\([^)]*\^|\.charCodeAt\([^)]*\)\s*\^|xor\s*\()', text, re.I):
        techniques.append('xor_encryption')
    
    # Unicode obfuscation
    unicode_weird = re.findall(r'[^\x00-\x7F]{3,}', text)
    if len(unicode_weird) > 3:
        techniques.append('unicode_obfuscation')
        details['unicode_sample_count'] = len(unicode_weird)
    
    # String array obfuscation (common in obfuscator.io)
    if re.search(r'var\s+_0x[a-f0-9]{4,}\s*=\s*\[', text, re.I):
        techniques.append('string_array_obfuscation')
    
    # Control flow flattening
    if re.search(r'while\s*\(\s*!!\s*\[\s*\]\s*\)', text):
        techniques.append('control_flow_flattening')
    
    # Dead code injection
    if text.count('function') > 50 and len(text) < 50000:
        techniques.append('dead_code_injection')
    
    # Set confidence
    confidence = 'high' if len(techniques) >= 3 else ('medium' if len(techniques) >= 2 else 'low')
    
    return {'techniques': techniques, 'confidence': confidence, 'details': details}

def load_config():
    """Load scan.yml knobs: scoring, allowlists, thresholds, build allowlist, domain allowlist."""
    cfg = {}
    try:
        cfg = yaml.safe_load(Path(SCAN_YML_PATH).read_text())
    except Exception:
        return {
            'scoring': {'rule_weights':{}, 'thresholds': {'suspicious':5,'malicious':8}},
            'analysis': {}
        }
    return cfg or {}

def domain_allowed(domain: str, allow_domains: list[str]) -> bool:
    if not domain:
        return True
    domain = domain.lower()
    for d in allow_domains:
        if domain == d or domain.endswith('.'+d):
            return True
    return False


def _build_newline_index(raw: bytes) -> list[int]:
    """Index newline offsets to recover line numbers for findings."""
    return [idx for idx, byte in enumerate(raw) if byte == 10]


def _sanitize_snippet(snippet: str, max_length: int = 240) -> str:
    cleaned = snippet.replace("\x00", "").strip()
    if len(cleaned) > max_length:
        return cleaned[: max_length - 3] + "..."
    return cleaned


def _location_from_offset(raw: bytes, newline_index: list[int], offset: int, length: int = 0, match: str | None = None) -> dict:
    if offset < 0:
        offset = 0
    span = max(length, 1)
    line_idx = bisect_right(newline_index, offset)
    last_break = newline_index[line_idx - 1] if line_idx else -1
    line_start = last_break + 1
    line_number = line_idx + 1
    column = (offset - line_start) + 1
    snippet_start = max(0, offset - 120)
    snippet_end = min(len(raw), offset + max(span, 60))
    snippet = _sanitize_snippet(raw[snippet_start:snippet_end].decode('utf-8', errors='ignore'))
    location: dict[str, object] = {"line": line_number, "column": column}
    if snippet:
        location["snippet"] = snippet
    if match:
        location["match"] = match
    return location


def _location_from_text_span(text: str | None, start: int, length: int = 0, match: str | None = None) -> dict | None:
    if text is None:
        return None
    if start < 0:
        start = 0
    span = max(length, 1)
    line_number = text.count('\n', 0, start) + 1
    line_start = text.rfind('\n', 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1
    column = (start - line_start) + 1
    snippet_start = max(0, start - 120)
    snippet_end = min(len(text), start + max(span, 60))
    snippet = _sanitize_snippet(text[snippet_start:snippet_end])
    location: dict[str, object] = {"line": line_number, "column": column}
    if snippet:
        location["snippet"] = snippet
    if match:
        location["match"] = match
    return location


def _clean_text(value) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    cleaned = value.replace("\x00", "").strip()
    return cleaned or None


def _normalize_author(author_data) -> tuple[str | None, str | None]:
    if not author_data:
        return None, None
    if isinstance(author_data, str):
        return _clean_text(author_data), None
    if isinstance(author_data, dict):
        name = _clean_text(
            author_data.get("name")
            or author_data.get("username")
            or author_data.get("login")
            or author_data.get("email")
        )
        url = _clean_text(author_data.get("url") or author_data.get("homepage") or author_data.get("web"))
        return name, url
    if isinstance(author_data, (list, tuple)) and author_data:
        for entry in author_data:
            name, url = _normalize_author(entry)
            if name:
                return name, url
    return None, None


def extract_package_metadata(root_dir: str) -> dict:
    base_path = Path(root_dir) / 'package' / 'package.json'
    if not base_path.exists():
        alt = next(Path(root_dir).rglob('package.json'), None)
        if alt:
            base_path = alt
    if not base_path.exists():
        return {}

    try:
        pkg = json.loads(base_path.read_text(errors='ignore'))
    except Exception:
        return {}

    description = _clean_text(pkg.get('description'))
    homepage = _clean_text(pkg.get('homepage'))

    repository_url = None
    repository = pkg.get('repository')
    if isinstance(repository, dict):
        repository_url = _clean_text(repository.get('url') or repository.get('web') or repository.get('https'))
    elif isinstance(repository, str):
        repository_url = _clean_text(repository)

    author_name, author_url = _normalize_author(pkg.get('author'))
    if not author_name:
        maintainers = pkg.get('maintainers')
        if isinstance(maintainers, list):
            for entry in maintainers:
                author_name, author_url = _normalize_author(entry)
                if author_name:
                    break
    npm_username = None
    publisher = pkg.get('publisher')
    if isinstance(publisher, dict):
        if not author_name:
            author_name = _clean_text(publisher.get('name') or publisher.get('username'))
        if not author_url:
            author_url = _clean_text(publisher.get('url'))
        npm_username = _clean_text(publisher.get('username'))
    elif isinstance(publisher, str):
        if not author_name:
            author_name = _clean_text(publisher)

    return {
        'author': author_name,
        'author_url': author_url,
        'description': description,
        'homepage': homepage,
        'repository': repository_url,
        'npm_username': npm_username,
    }

def classify_script(command: str, benign_re: re.Pattern):
    """Tag a lifecycle script command for risk."""
    tags = []
    if SHELL_RE.search(command): tags.append('shell_spawn')
    if DOWNLOADER_RE.search(command): tags.append('downloader')
    if re.search(r'\bnode\b.+\b(child_process|eval|Function)\b', command, re.I):
        tags.append('node_shellish')
    if re.search(r'\bbundle\.js\b', command, re.I):
        tags.append('bundle_exec')
        if benign_re.search(command): tags.append('benign_build')
    if re.search(r'https?://', command, re.I): tags.append('url_in_command')
    return tags

def load_yara_rules(cfg):
    """Load and compile YARA rules from configured path with error handling."""
    if not YARA_AVAILABLE:
        return None
    
    yara_cfg = cfg.get('analysis', {}).get('yara', {})
    if not yara_cfg.get('enabled', False):
        return None
    
    rules_path = yara_cfg.get('rules_path', 'yara-rules/packages/full/yara-rules-full.yar')
    
    # Try multiple path locations (local dev vs Docker)
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
        print(f"YARA rules not found at {rules_path}, YARA scanning disabled")
        return None
    
    try:
        print(f"Loading YARA rules from {rules_file}...")
        compiled_rules = yara.compile(filepath=str(rules_file))
        print(f"YARA rules loaded successfully")
        return compiled_rules
    except Exception as e:
        print(f"Failed to compile YARA rules: {e}")
        return None

def determine_yara_severity(match):
    """Map YARA rule tags to severity level."""
    tags = [t.lower() for t in match.tags]
    
    # High severity indicators
    high_tags = {'critical', 'exploit', 'malware', 'ransomware', 'backdoor', 'trojan', 'rootkit', 'apt'}
    if any(tag in high_tags for tag in tags):
        return 'high'
    
    # Medium severity indicators  
    medium_tags = {'suspicious', 'pua', 'webshell', 'cryptominer', 'dropper', 'downloader', 'stealer'}
    if any(tag in medium_tags for tag in tags):
        return 'medium'
    
    # Default to low
    return 'low'

def scan_file_with_yara(file_path: Path, yara_rules, yara_cfg: dict):
    """Scan a single file with YARA rules and return findings with detailed context."""
    if not yara_rules:
        return []
    
    findings = []
    max_size = yara_cfg.get('max_file_size_mb', 10) * 1024 * 1024
    timeout = yara_cfg.get('timeout_seconds', 30)
    
    try:
        file_size = file_path.stat().st_size
        if file_size > max_size:
            return []  # Skip large files
        
        # Read file content for context extraction
        try:
            file_content = file_path.read_bytes()
        except Exception:
            file_content = b''
        
        # Run YARA scan with timeout
        matches = yara_rules.match(str(file_path), timeout=timeout)
        
        for match in matches:
            severity = determine_yara_severity(match)
            
            # Extract matched strings with context (limit to first 10)
            matched_strings = []
            for string_match in match.strings[:10]:
                try:
                    # string_match is tuple: (offset, identifier, data)
                    offset = string_match[0]
                    identifier = string_match[1]
                    data = string_match[2]
                    
                    # Calculate line number from offset
                    line_num = file_content[:offset].count(b'\n') + 1 if file_content else 0
                    
                    # Extract surrounding context (100 chars before/after)
                    context_start = max(0, offset - 100)
                    context_end = min(len(file_content), offset + len(data) + 100)
                    context = file_content[context_start:context_end]
                    
                    if isinstance(data, bytes):
                        data_str = data.decode('utf-8', errors='ignore')[:200]
                    else:
                        data_str = str(data)[:200]
                    
                    context_str = context.decode('utf-8', errors='ignore')[:300]
                    
                    # Truncate if too long
                    if len(data_str) > 150:
                        data_str = data_str[:150] + '...'
                    if len(context_str) > 250:
                        context_str = '...' + context_str[-247:]
                    
                    matched_strings.append({
                        'identifier': identifier.decode('utf-8') if isinstance(identifier, bytes) else str(identifier),
                        'offset': offset,
                        'line_number': line_num,
                        'matched_data': data_str,
                        'data_length': len(data),
                        'context': context_str  # Surrounding code for analysis
                    })
                except Exception as e:
                    continue
            
            # Extract metadata
            metadata = {}
            if hasattr(match, 'meta'):
                metadata = dict(match.meta)
            
            # Get file name and relative path
            file_name = file_path.name
            rel_path = str(file_path)
            
            # Create detailed explanation
            rule_desc = metadata.get('description', 'No description available')
            tags_str = ', '.join(match.tags[:5]) if match.tags else 'suspicious'
            
            explanation = f'YARA rule "{match.rule}" triggered on {file_name}'
            if matched_strings:
                explanation += f' at line {matched_strings[0]["line_number"]}'
            explanation += f'. Pattern type: {tags_str}. {rule_desc}'
            
            findings.append({
                'rule': 'yara_match',
                'severity': severity,
                'details': {
                    'path': rel_path,
                    'file_name': file_name,
                    'file_size_bytes': file_size,
                    'yara_rule': match.rule,
                    'yara_namespace': match.namespace if hasattr(match, 'namespace') else None,
                    'yara_tags': list(match.tags),
                    'yara_metadata': metadata,
                    'matched_strings': matched_strings[:5],  # Limit to 5 best matches
                    'match_count': len(match.strings),
                    'explanation': explanation
                }
            })
    
    except yara.TimeoutError:
        print(f"YARA timeout scanning {file_path}")
    except Exception as e:
        # Silently skip files that can't be scanned
        pass
    
    return findings

def analyze_file_bytes(path: Path, b: bytes, allow_domains: list[str]):
    """Return list of finding dicts for a single file’s bytes."""
    rel = str(path)
    out = []
    newline_index = _build_newline_index(b)
    try:
        text = b.decode('utf-8', errors='ignore')
    except Exception:
        text = None

    # URLs (explicit) + allowlist check - deduplicate and show unique domains
    url_matches = list(URL_RE.finditer(b))
    domain_entries: dict[str, dict] = {}

    for match in url_matches:
        raw_value = match.group(0)
        if isinstance(raw_value, tuple):
            raw_value = raw_value[0]
        if isinstance(raw_value, bytes):
            url = raw_value.decode('utf-8', 'ignore')
        else:
            url = str(raw_value)

        try:
            parsed = urlparse(url)
            domain = parsed.netloc or ''
        except Exception:
            domain = ''

        if not domain:
            continue

        entry = domain_entries.setdefault(domain, {'count': 0, 'urls': [], 'locations': []})
        entry['count'] += 1
        if len(entry['urls']) < 5:
            entry['urls'].append(url)

        if len(entry['locations']) < 5:
            entry['locations'].append(
                _location_from_offset(b, newline_index, match.start(), len(match.group(0)), url)
            )

    for domain, info in domain_entries.items():
        severity = 'medium'
        details = {
            'path': rel,
            'domain': domain,
            'url_count': info['count'],
            'sample_urls': info['urls'][:3],
            'locations': info['locations'],
        }
        if allow_domains and not domain_allowed(domain, allow_domains):
            severity = 'high'
            details['explanation'] = f'Non-allowlisted domain {domain} found in code - potential exfil or C2 endpoint'
            out.append({'rule': 'url_outside_allowlist', 'severity': severity, 'details': details})
        else:
            out.append({'rule': 'url_in_code', 'severity': severity, 'details': details})

    # network client usage - extract what method and context
    net_matches = list(NET_CLIENT_RE.finditer(b))
    if net_matches:
        methods: list[str] = []
        locations: list[dict] = []
        for match in net_matches[:20]:
            value = match.group(0)
            if isinstance(value, bytes):
                method = value.decode('utf-8', 'ignore')
            elif isinstance(value, tuple):
                parts = []
                for part in value:
                    if isinstance(part, bytes):
                        parts.append(part.decode('utf-8', 'ignore'))
                    else:
                        parts.append(str(part))
                method = ' '.join([p for p in parts if p])
            else:
                method = str(value)

            if method and method not in methods and len(methods) < 10:
                methods.append(method)
            if len(locations) < 5:
                locations.append(_location_from_offset(b, newline_index, match.start(), len(match.group(0)), method))
        out.append({
            'rule':'net_client_usage',
            'severity':'medium',
            'details':{
                'path': rel,
                'methods': methods,
                'explanation': f'Network client usage detected: {", ".join(methods)} - package makes outbound HTTP requests',
                'locations': locations,
            }
        })

    # C2 / webhook destinations - extract the actual full URLs
    c2_matches = list(C2_RE.finditer(b))
    if c2_matches:
        normalized_c2 = []
        c2_locations: list[dict] = []
        for match in c2_matches:
            raw_value = match.group(0)
            if isinstance(raw_value, tuple):
                raw_value = raw_value[0]
            if isinstance(raw_value, (bytes, bytearray)):
                value = raw_value.decode('utf-8', 'ignore')
            else:
                value = str(raw_value)
            if value:
                normalized_c2.append(value)
                if len(c2_locations) < 5:
                    c2_locations.append(_location_from_offset(b, newline_index, match.start(), len(match.group(0)), value))
        # Get full URLs containing these C2 domains
        c2_urls = []
        for url_match in URL_RE.findall(b):
            url_str = url_match.decode('utf-8', 'ignore')
            if any(c2.lower() in url_str.lower() for c2 in normalized_c2):
                c2_urls.append(url_str)
        c2_urls = list(set(c2_urls[:5]))  # dedupe, limit to 5
        
        endpoints = list(set(normalized_c2[:5]))
        out.append({
            'rule':'c2_webhook',
            'severity':'high',
            'details':{
                'path': rel,
                'endpoints': endpoints,
                'full_urls': c2_urls,
                'explanation': f'Known C2/webhook endpoint detected: {endpoints[0]} - likely exfiltration channel (Full URLs: {c2_urls[0] if c2_urls else "N/A"})',
                'locations': c2_locations,
            }
        })

    # FS write candidates - extract target paths
    fs_write_matches = list(FS_WRITE_RE.finditer(b))
    if fs_write_matches:
        write_methods = []
        base_locations: list[dict] = []
        for match in fs_write_matches[:10]:
            raw_value = match.group(0)
            if isinstance(raw_value, bytes):
                method = raw_value.decode('utf-8', 'ignore')
            elif isinstance(raw_value, tuple):
                method_parts = []
                for part in raw_value:
                    if isinstance(part, bytes):
                        method_parts.append(part.decode('utf-8', 'ignore'))
                    else:
                        method_parts.append(str(part))
                method = ' '.join([p for p in method_parts if p])
            else:
                method = str(raw_value)
            if method and method not in write_methods and len(write_methods) < 5:
                write_methods.append(method)
            if len(base_locations) < 5:
                base_locations.append(_location_from_offset(b, newline_index, match.start(), len(match.group(0)), method))
        sev = 'medium'
        
        # Extract suspicious target paths
        suspicious_matches = list(OUTSIDE_PATH_HINT_RE.finditer(b))
        if suspicious_matches:
            sev = 'high'
            paths_decoded = []
            path_locations: list[dict] = []
            for match in suspicious_matches[:5]:
                raw_value = match.group(0)
                if isinstance(raw_value, bytes):
                    value = raw_value.decode('utf-8', 'ignore')
                elif isinstance(raw_value, tuple):
                    parts = []
                    for part in raw_value:
                        if isinstance(part, bytes):
                            parts.append(part.decode('utf-8', 'ignore'))
                        else:
                            parts.append(str(part))
                    value = ' '.join([p for p in parts if p])
                else:
                    value = str(raw_value)
                if value and value not in paths_decoded:
                    paths_decoded.append(value)
                if len(path_locations) < 5:
                    path_locations.append(_location_from_offset(b, newline_index, match.start(), len(match.group(0)), value))
            out.append({
                'rule':'writes_outside_pkg',
                'severity':sev,
                'details':{
                    'path': rel,
                    'write_methods': write_methods,
                    'target_paths': paths_decoded,
                    'explanation': f'File writes to sensitive paths detected: {", ".join(paths_decoded[:3])} - potential credential theft or persistence',
                    'locations': path_locations or base_locations,
                }
            })
        else:
            out.append({
                'rule':'writes_outside_pkg_candidate',
                'severity':sev,
                'details':{
                    'path': rel,
                    'write_methods': write_methods,
                    'locations': base_locations,
                }
            })

    # CI-evasion - extract what env vars are being checked
    ci_matches = list(CI_EVASION_RE.finditer(b))
    if ci_matches:
        checks = []
        locations: list[dict] = []
        for match in ci_matches[:10]:
            raw_value = match.group(0)
            if isinstance(raw_value, bytes):
                value = raw_value.decode('utf-8', 'ignore')
            elif isinstance(raw_value, tuple):
                parts = []
                for part in raw_value:
                    if isinstance(part, bytes):
                        parts.append(part.decode('utf-8', 'ignore'))
                    else:
                        parts.append(str(part))
                value = ' '.join([p for p in parts if p])
            else:
                value = str(raw_value)
            if value and value not in checks and len(checks) < 5:
                checks.append(value)
            if len(locations) < 5:
                locations.append(_location_from_offset(b, newline_index, match.start(), len(match.group(0)), value))
        out.append({
            'rule':'ci_evasion',
            'severity':'low',
            'details':{
                'path': rel,
                'checks': checks,
                'locations': locations,
            }
        })

    # Env snoop explicit
    if text and ENV_KEYS_RE.search(text):
        matched_keys = []
        locations: list[dict] = []
        for match in ENV_KEYS_RE.finditer(text):
            key = match.group(0)
            if key and key not in matched_keys and len(matched_keys) < 10:
                matched_keys.append(key)
            if len(locations) < 5:
                loc = _location_from_text_span(text, match.start(), len(match.group(0)), key)
                if loc:
                    locations.append(loc)
        out.append({
            'rule':'env_snoop',
            'severity':'medium',
            'details':{
                'path': rel,
                'env_keys': matched_keys,
                'explanation':f'Access to sensitive environment variables detected: {", ".join(matched_keys[:5])} - potential credential exfiltration',
                'locations': locations,
            }
        })

    # Webpack / huge minified bundle
    if path.suffix.lower() in ('.js', '.mjs', '.cjs'):
        if len(b) >= BIG_JS_BYTES:
            mb = round(len(b) / 1024 / 1024, 2)
            out.append({
                'rule':'large_js',
                'severity':'medium',
                'details':{
                    'path': rel, 
                    'bytes': len(b),
                    'explanation':f'Large JavaScript file ({mb}MB) detected - may hide malicious payload in bundled code',
                    'locations': [_location_from_offset(b, newline_index, 0, 1)],
                }
            })
        if WEBPACK_BOOTSTRAP_RE.search(b):
            out.append({'rule':'webpack_bundle','severity':'medium','details':{'path': rel}})
        long_line_match = VERY_LONG_LINE_RE.search(b)
        if long_line_match:
            out.append({
                'rule': 'minified_long_lines',
                'severity': 'low',
                'details': {
                    'path': rel,
                    'locations': [_location_from_offset(b, newline_index, long_line_match.start(), len(long_line_match.group(0)))],
                },
            })

    # obfuscation v2: high entropy or mega-base64
    ent = shannon_entropy(b)
    if ent >= HIGH_ENTROPY and len(b) > 10_000:
        out.append({
            'rule':'high_entropy_blob',
            'severity':'medium',
            'details':{
                'path': rel, 
                'entropy': round(ent,2), 
                'bytes': len(b),
                'explanation':f'High entropy ({round(ent,2)}) indicates packed/encrypted payload - possible obfuscation',
                'locations': [_location_from_offset(b, newline_index, 0, len(b[:200]))],
            }
        })
    
    # Extract and decode base64 blobs
    base64_iter = list(re.finditer(rb'(?:[A-Za-z0-9+/]{120,}={0,2})', b))
    if base64_iter:
        for match in base64_iter[:3]:  # Limit to first 3 blobs
            try:
                decoded = base64.b64decode(match.group(0)[:200])  # Decode first 200 chars
                preview = decoded[:100].decode('utf-8', errors='ignore')
                if not preview.isprintable():
                    preview = f"<binary data: {len(decoded)} bytes>"
            except Exception:
                preview = "<decode failed>"
            
            out.append({
                'rule':'big_base64_blob',
                'severity':'medium',
                'details':{
                    'path': rel, 
                    'size': len(b),
                    'blob_length': len(match.group(0)),
                    'decoded_preview': preview,
                    'explanation':'Large base64-encoded blob detected - may hide malicious executable or shellcode',
                    'locations': [_location_from_offset(b, newline_index, match.start(), len(match.group(0)))],
                }
            })

    # Native / WASM binaries
    if b.startswith(WASM_MAGIC):
        out.append({
            'rule':'wasm_present',
            'severity':'medium',
            'details':{
                'path': rel,
                'explanation':'WebAssembly binary detected - may execute compiled code outside Node sandbox'
            }
        })
    if b.startswith(PE_MAGIC) or b.startswith(ELF_MAGIC) or any(b.startswith(m) for m in MACHO_MAGICS):
        out.append({
            'rule':'native_binary_present',
            'severity':'high',
            'details':{
                'path': rel,
                'explanation':'Native executable (PE/ELF/Mach-O) found in package - highly suspicious for npm library'
            }
        })

    # node-pre-gyp / prebuild-install hints
    if PREBUILD_RE.search(b):
        out.append({'rule':'native_fetcher_present','severity':'low','details':{'path': rel}})

    # Generic suspicious (legacy) - extract actual matches
    for pat in GENERIC_SUSPICIOUS_PATTERNS:
        matches_iter = list(pat.finditer(b))
        if matches_iter:
            samples = []
            locations: list[dict] = []
            for match in matches_iter[:10]:
                groups = match.groups()
                if groups:
                    sample_parts = []
                    for grp in groups:
                        if isinstance(grp, bytes):
                            sample_parts.append(grp.decode('utf-8', 'ignore'))
                        else:
                            sample_parts.append(str(grp))
                    sample = ' '.join([p for p in sample_parts if p])
                else:
                    raw_value = match.group(0)
                    if isinstance(raw_value, bytes):
                        sample = raw_value.decode('utf-8', 'ignore')
                    else:
                        sample = str(raw_value)
                if sample and sample not in samples:
                    samples.append(sample)
                if len(locations) < 5:
                    locations.append(_location_from_offset(b, newline_index, match.start(), len(match.group(0)), sample))
            samples = samples[:5]
            
            out.append({
                'rule':'suspicious_pattern',
                'severity':'medium',
                'details':{
                    'path': rel, 
                    'pattern': pat.pattern.decode('utf-8','ignore'),
                    'samples': samples,
                    'locations': locations,
                }
            })

    return out

def analyze_html_content(path: Path, b: bytes, allow_domains: list[str]) -> list:
    """Analyze HTML/HTM/PHP files for phishing patterns."""
    out = []
    rel = str(path.relative_to(path.parents[2])) if len(path.parents) > 2 else str(path)
    
    # Credential input detection
    has_password = PASSWORD_INPUT_RE.search(b)
    has_credential = CREDENTIAL_FORM_RE.search(b)
    
    if has_password or has_credential:
        # Extract form action URLs
        form_actions = FORM_ACTION_RE.findall(b)
        external_actions = []
        
        for action in form_actions:
            try:
                action_str = action.decode('utf-8', 'ignore')
                if action_str.startswith('http'):
                    parsed = urlparse(action_str)
                    if allow_domains and not domain_allowed(parsed.netloc, allow_domains):
                        external_actions.append(action_str)
            except:
                pass
        
        if external_actions:
            out.append({
                'rule': 'phishing_form',
                'severity': 'high',
                'details': {
                    'path': rel,
                    'form_actions': external_actions[:5],
                    'explanation': f'Credential input form submits to external domain: {external_actions[0]}'
                }
            })
    
    # Fake CAPTCHA detection
    if FAKE_CAPTCHA_RE.search(b) or SUSPICIOUS_BUTTON_RE.search(b):
        button_texts = SUSPICIOUS_BUTTON_RE.findall(b)
        samples = [m.decode('utf-8', 'ignore') for m in button_texts[:3]] if button_texts else []
        
        out.append({
            'rule': 'fake_captcha',
            'severity': 'medium',
            'details': {
                'path': rel,
                'button_samples': samples,
                'explanation': 'Fake CAPTCHA or ClickFix pattern detected - may trick users into malicious actions'
            }
        })
    
    # CDN loading detection
    cdn_matches = CDN_LOAD_RE.findall(b)
    if cdn_matches:
        cdn_urls = []
        for script_src in SCRIPT_SRC_RE.findall(b) + LINK_HREF_RE.findall(b):
            url_str = script_src.decode('utf-8', 'ignore')
            if any(cdn in url_str for cdn in ['unpkg.com', 'jsdelivr.net', 'cdnjs', 'esm.sh', 'skypack']):
                cdn_urls.append(url_str)
        
        cdn_urls = list(set(cdn_urls[:10]))
        out.append({
            'rule': 'external_cdn_load',
            'severity': 'medium',
            'details': {
                'path': rel,
                'cdn_urls': cdn_urls,
                'cdn_count': len(cdn_urls),
                'explanation': f'Loads external CDN resources ({len(cdn_urls)} detected) - common evasion tactic'
            }
        })
    
    # Iframe embedding
    iframe_srcs = IFRAME_RE.findall(b)
    if iframe_srcs:
        iframe_urls = [src.decode('utf-8', 'ignore') for src in iframe_srcs[:5]]
        out.append({
            'rule': 'iframe_embed',
            'severity': 'medium',
            'details': {
                'path': rel,
                'iframe_urls': iframe_urls,
                'explanation': f'Embeds external content via iframe: {iframe_urls[0]}'
            }
        })
    
    return out

def analyze_python_script(path: Path, b: bytes) -> list:
    """Analyze Python scripts for web servers and suspicious downloads."""
    out = []
    rel = str(path.relative_to(path.parents[2])) if len(path.parents) > 2 else str(path)
    
    # Web server detection
    server_matches = PYTHON_SERVER_RE.findall(b)
    if server_matches:
        frameworks = list(set([m.decode('utf-8', 'ignore') for m in server_matches[:5]]))
        out.append({
            'rule': 'http_server',
            'severity': 'medium',
            'details': {
                'path': rel,
                'frameworks': frameworks,
                'explanation': f'Python web server detected: {frameworks[0]} - suspicious in npm package'
            }
        })
    
    # Socket/port binding
    socket_matches = PYTHON_SOCKET_RE.findall(b)
    if socket_matches:
        out.append({
            'rule': 'port_binding',
            'severity': 'medium',
            'details': {
                'path': rel,
                'explanation': 'Socket binding detected - may open network listener'
            }
        })
    
    # Downloads in Python
    download_matches = PYTHON_DOWNLOAD_RE.findall(b)
    if download_matches:
        methods = list(set([m[0].decode('utf-8', 'ignore') if isinstance(m, tuple) else m.decode('utf-8', 'ignore') for m in download_matches[:5]]))
        out.append({
            'rule': 'script_download',
            'severity': 'medium',
            'details': {
                'path': rel,
                'methods': methods,
                'explanation': f'Python script downloads content: {", ".join(methods)}'
            }
        })
    
    return out

def safe_extract(tar: tarfile.TarFile, path: str = ".", max_bytes: int | None = None):
    """Secure extraction: block traversal, cap size, and report symlinks (escape)."""
    if max_bytes is None or max_bytes <= 0:
        max_bytes = MAX_BYTES if MAX_BYTES > 0 else None
    total = 0
    symlink_findings = []
    root_abs = os.path.abspath(path)
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        abs_member = os.path.abspath(member_path)
        if not os.path.commonpath([root_abs, abs_member]) == root_abs:
            raise Exception("Path traversal in tarball: " + member.name)
        if member.isfile():
            total += member.size
            if max_bytes and total > max_bytes:
                raise Exception("Extraction size limit exceeded")
        # detect symlinks
        if member.issym() or member.islnk():
            # If the target is absolute or uses .., consider risky
            link_target = member.linkname or ''
            if link_target.startswith('/') or '..' in link_target:
                symlink_findings.append({'rule':'symlink_escape','severity':'high','details':{'entry': member.name, 'target': link_target}})
    tar.extractall(path)
    return symlink_findings

# ---------------------------
# Package Scan
# ---------------------------
def scan_package(dirpath, allow_domains: list[str], benign_build_re: re.Pattern, yara_rules=None, yara_cfg=None):
    findings = []
    yara_cfg = yara_cfg or {}
    pkg_path = Path(dirpath) / 'package' / 'package.json'
    if not pkg_path.exists():
        alt = next(Path(dirpath).rglob('package.json'), None)
        if alt: pkg_path = alt
    if not pkg_path.exists():
        findings.append({'rule':'no_package_json','severity':'low','details':None})
        return findings

    # parse package.json
    try:
        pkg = json.loads(pkg_path.read_text(errors='ignore'))
    except Exception:
        pkg = {}

    # Typosquat detection
    package_name = pkg.get('name', '')
    if package_name:
        typosquat_result = detect_typosquat(package_name)
        if typosquat_result['is_typosquat']:
            findings.append({
                'rule': 'typosquat_detected',
                'severity': 'high',
                'details': {
                    'package_name': package_name,
                    'target_package': typosquat_result['target_package'],
                    'similarity': typosquat_result['similarity'],
                    'edit_distance': typosquat_result['edit_distance'],
                    'typosquat_type': typosquat_result['typosquat_type'],
                    'explanation': f'Package "{package_name}" appears to typosquat "{typosquat_result["target_package"]}" ({typosquat_result["similarity"]}% similar, type: {typosquat_result["typosquat_type"]})'
                }
            })

    # quick packaging checks
    # .npmrc in tarball?
    if any((Path(dirpath)/'package'/'.npmrc').exists() or (p.name == '.npmrc') for p in Path(dirpath).rglob('.npmrc')):
        findings.append({'rule':'npmrc_present','severity':'high','details':{}})

    # lockfiles / shrinkwrap present
    for lf in LOCKFILES:
        if any(p.name == lf for p in Path(dirpath).rglob(lf)):
            findings.append({'rule':'lockfile_present','severity':'low','details':{'file': lf}})

    # lifecycle analysis with tagging
    scripts = pkg.get('scripts',{}) or {}
    has_risky_script = False
    risky_script_context = []

    for k in LIFECYCLE_KEYS:
        cmd = scripts.get(k)
        if not cmd: continue
        tags = classify_script(cmd, benign_build_re)
        sev = 'high' if any(t in tags for t in ['shell_spawn','downloader','node_shellish','bundle_exec']) else 'medium'
        # downgrade if only benign build
        if sev == 'medium' and tags == ['benign_build']:
            sev = 'low'
        detail = {'key':k, 'value':cmd, 'tags':tags}

        # Extract URLs from command
        for m in re.findall(r'https?://[^\s\'"]+', cmd, flags=re.I):
            try:
                d = urlparse(m).netloc
            except Exception:
                d = ''
            if allow_domains and not domain_allowed(d, allow_domains):
                findings.append({
                    'rule':'url_outside_allowlist',
                    'severity':'high',
                    'details':{
                        'path':'<lifecycle:cmd>', 
                        'url': m, 
                        'domain': d, 
                        'hook': k,
                        'explanation':f'Lifecycle hook {k} downloads from non-allowlisted domain {d} - potential trojan dropper'
                    }
                })
            else:
                findings.append({'rule':'url_in_code','severity':'medium','details':{'path':'<lifecycle:cmd>', 'url': m, 'domain': d, 'hook': k}})

        # Add human explanation for lifecycle scripts
        if sev == 'high':
            detail['explanation'] = f'High-risk {k} hook: {", ".join(tags)} - may execute arbitrary code during install'
        elif sev == 'medium' and 'benign_build' not in tags:
            detail['explanation'] = f'{k} hook with moderate risk: {", ".join(tags)}'
        
        findings.append({'rule':'lifecycle_script','severity': sev, 'details': detail})
        if sev in ('high','medium') and any(t in tags for t in ['shell_spawn','downloader','node_shellish','bundle_exec']):
            has_risky_script = True
            risky_script_context.append({'key':k, 'tags':tags})

    # bin hint
    if 'bin' in pkg:
        findings.append({'rule':'has_bin','severity':'low','details':{'bin':pkg.get('bin')}})

    # node-pre-gyp/prebuild-install in scripts (mirrors)
    if any(re.search(r'(prebuild-install|node-pre-gyp)', scripts.get(k,''), re.I) for k in scripts):
        findings.append({'rule':'native_fetcher_present','severity':'low','details':{'where':'scripts'}})
        if re.search(r'(--download|--build-from-source|--target|--runtime)\s+https?://', json.dumps(scripts), re.I):
            findings.append({'rule':'native_fetcher_custom_url','severity':'medium','details':{}})

    # walk files & analyze
    for f in Path(dirpath).rglob('*'):
        if not f.is_file():
            continue
        suffix = f.suffix.lower()
        
        # Inline YARA scanning (enabled when rules are loaded in this process)
        if yara_rules:
            findings.extend(scan_file_with_yara(f, yara_rules, yara_cfg))

        # Existing JS/JSON analysis
        if suffix in ['.js','.mjs','.cjs','.json','.ts','']:
            try:
                b = f.read_bytes()
            except Exception:
                continue
            findings.extend(analyze_file_bytes(f, b, allow_domains))
            
            # Enhanced obfuscation detection for JS files
            if suffix in ['.js', '.mjs', '.cjs'] and len(b) > 1000:
                obf_result = analyze_obfuscation(b)
                if obf_result['techniques']:
                    rel = str(f.relative_to(Path(dirpath))) if f.is_relative_to(Path(dirpath)) else str(f)
                    findings.append({
                        'rule': 'advanced_obfuscation',
                        'severity': 'high' if obf_result['confidence'] == 'high' else 'medium',
                        'details': {
                            'path': rel,
                            'techniques': obf_result['techniques'],
                            'confidence': obf_result['confidence'],
                            'obfuscation_details': obf_result['details'],
                            'explanation': f'Advanced obfuscation detected ({obf_result["confidence"]} confidence): {", ".join(obf_result["techniques"])}'
                        }
                    })
        
        # HTML/PHP phishing analysis
        elif suffix in ['.html', '.htm', '.php']:
            try:
                b = f.read_bytes()
            except Exception:
                continue
            findings.extend(analyze_html_content(f, b, allow_domains))
        
        # Python script analysis
        elif suffix in ['.py']:
            try:
                b = f.read_bytes()
            except Exception:
                continue
            findings.extend(analyze_python_script(f, b))
        
        # Shell script analysis
        elif suffix in ['.sh', '.bash', '.cmd', '.ps1']:
            try:
                b = f.read_bytes()
            except Exception:
                continue
            # Check for downloads in shell scripts
            if SCRIPT_DOWNLOAD_RE.search(b):
                rel = str(f.relative_to(Path(dirpath))) if f.is_relative_to(Path(dirpath)) else str(f)
                findings.append({
                    'rule': 'script_download',
                    'severity': 'high',
                    'details': {
                        'path': rel,
                        'explanation': 'Shell script downloads from internet during install'
                    }
                })

    # contextual upgrades (install chain)
    has_env = any(x['rule'] == 'env_snoop' for x in findings)
    has_net = any(x['rule'] in ('url_in_code','url_outside_allowlist','net_client_usage','c2_webhook') for x in findings)
    has_bundle = any(x['rule'] in ('webpack_bundle','large_js') for x in findings)
    writes_outside = any(x['rule'] == 'writes_outside_pkg' for x in findings)

    if has_risky_script and (has_env or has_net or has_bundle):
        findings.append({
            'rule':'install_chain_risk',
            'severity':'high',
            'details': {
                'explanation':'Lifecycle script launches shell/downloader and code references env/URLs/bundles.',
                'lifecycle': risky_script_context
            }
        })
    if has_risky_script and writes_outside:
        findings.append({
            'rule':'install_persistence_risk',
            'severity':'high',
            'details': {
                'explanation':'Lifecycle script plus writes outside package (potential persistence/creds write).',
                'lifecycle': risky_script_context
            }
        })

    return findings

# ---------------------------
# Tarball → Analyze
# ---------------------------
def parse_name_version_from_filename(base_name: str):
    # downloads files are formatted like scope__name@version.tgz or name@version.tgz
    try:
        if '@' in base_name:
            nv = base_name.split('@')
            version = nv[-1]
            name_part = '@'.join(nv[:-1])
            name = name_part.replace('__', '/')
            return name, version
    except Exception:
        pass
    return None, None

def analyze_tgz(tgz_path, allow_domains: list[str], benign_build_re: re.Pattern, yara_rules=None, yara_cfg=None, max_extract_bytes: int | None = None):
    base = Path(tgz_path).stem
    tmp = tempfile.mkdtemp(prefix='pkginferno-')
    try:
        package_meta: dict = {}
        with tarfile.open(tgz_path, 'r:gz') as t:
            symlink_finds = safe_extract(t, tmp, max_extract_bytes)
        findings = symlink_finds + scan_package(tmp, allow_domains, benign_build_re, yara_rules, yara_cfg)
        package_meta = extract_package_metadata(tmp)
        out = {'tgz': str(tgz_path), 'findings': findings}
        out_path = Path(FINDINGS_DIR) / (base + '.findings.json')
        out_path.write_text(json.dumps(out, indent=2))
        print('wrote findings', out_path)
        name, version = parse_name_version_from_filename(base)
        return name, version, findings, package_meta
    except Exception as e:
        msg = str(e)
        # Convert extraction size limit into a recorded finding rather than a hard error
        if 'Extraction size limit exceeded' in msg:
            name, version = parse_name_version_from_filename(base)
            finding = {
                'rule': 'extraction_limit_exceeded',
                'severity': 'low',
                'details': {
                    'path': str(tgz_path),
                    'max_extract_bytes': max_extract_bytes if max_extract_bytes and max_extract_bytes > 0 else (MAX_BYTES if MAX_BYTES > 0 else None),
                    'explanation': 'Tarball skipped because it exceeds extraction byte limit'
                }
            }
            out = {'tgz': str(tgz_path), 'findings': [finding]}
            out_path = Path(FINDINGS_DIR) / (base + '.findings.json')
            out_path.write_text(json.dumps(out, indent=2))
            print('wrote findings', out_path)
            return name, version, [finding], {}
        print('analyze error', tgz_path, e)
        if os.environ.get('DEBUG_ANALYZER_EXCEPTIONS') == '1':
            traceback.print_exc()
        return None, None, [], {}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ---------------------------
# Scoring / DB I/O
# ---------------------------
def load_scoring(cfg):
    try:
        return cfg.get('scoring', {})
    except Exception:
        return { 'rule_weights': {}, 'thresholds': {'suspicious': 5, 'malicious': 8} }

def score_findings(findings, scoring):
    weights = scoring.get('rule_weights', {})
    score = 0
    for f in findings:
        rule = f['rule']
        w = 0
        if rule == 'lifecycle_script':
            w = weights.get('lifecycle_exec', 0)
        elif rule in ('suspicious_pattern', 'minified_long_lines'):
            w = weights.get('suspicious_strings', 0)
        elif rule in ('big_base64_blob','high_entropy_blob'):
            w = weights.get('obfuscation', 0)
        elif rule == 'has_bin':
            w = weights.get('new_bin_added', 0)
        elif rule in ('url_in_code','net_client_usage'):
            w = weights.get('network_ioc', 0)
        elif rule == 'url_outside_allowlist':
            w = max(weights.get('network_ioc', 0), 1) + 1
        elif rule == 'env_snoop':
            w = weights.get('env_access', 0)
        elif rule in ('webpack_bundle','large_js'):
            w = weights.get('packed_bundle', 0)
        elif rule == 'ci_evasion':
            w = weights.get('ci_evasion', 0)
        elif rule == 'c2_webhook':
            w = weights.get('c2_webhook', 0)
        elif rule in ('writes_outside_pkg','writes_outside_pkg_candidate'):
            w = weights.get('writes_outside_pkg', 0)
        elif rule in ('native_binary_present','wasm_present','native_fetcher_present','native_fetcher_custom_url'):
            w = weights.get('native_payload', 0)
        elif rule == 'npmrc_present':
            w = weights.get('npmrc_present', 0)
        elif rule == 'lockfile_present':
            w = weights.get('lockfile_present', 0)
        elif rule in ('install_chain_risk','install_persistence_risk'):
            w = max(weights.get('network_ioc',0), weights.get('env_access',0)) + weights.get('lifecycle_exec',0) + 1
        elif rule == 'phishing_form':
            w = max(weights.get('c2_webhook', 0), weights.get('network_ioc', 0)) + 2
        elif rule in ('fake_captcha', 'external_cdn_load', 'iframe_embed'):
            w = weights.get('network_ioc', 0) + 1
        elif rule in ('http_server', 'port_binding'):
            w = weights.get('writes_outside_pkg', 0)
        elif rule == 'script_download':
            w = weights.get('network_ioc', 0) + weights.get('lifecycle_exec', 0)
        elif rule == 'typosquat_detected':
            w = weights.get('typosquat', 8)  # High score for typosquatting
        elif rule == 'advanced_obfuscation':
            w = weights.get('advanced_obfuscation', 5) if f.get('details', {}).get('confidence') == 'high' else weights.get('obfuscation', 3)
        elif rule == 'yara_match':
            # Use severity-specific weights for YARA matches
            severity = f.get('severity', 'low')
            if severity == 'high':
                w = weights.get('yara_match_high', 7)
            elif severity == 'medium':
                w = weights.get('yara_match_medium', 4)
            else:
                w = weights.get('yara_match_low', 2)
        score += int(w)

    thresholds = scoring.get('thresholds', {'suspicious':6,'malicious':12})
    label = 'clean'
    if score >= thresholds.get('malicious', 12):
        label = 'malicious'
    elif score >= thresholds.get('suspicious', 6):
        label = 'suspicious'
    return score, label

def get_db_conn():
    if DB_URL:
        try:
            conn = psycopg2.connect(DB_URL)
            conn.autocommit = False
            return conn
        except Exception as e:
            print('db connect failed (DB_URL)', e)
            return None
    if not (DB_SECRET_NAME and DB_ENDPOINT):
        return None
    try:
        sm = boto3.client('secretsmanager', region_name=AWS_REGION)
        sec = sm.get_secret_value(SecretId=DB_SECRET_NAME)
        creds = json.loads(sec.get('SecretString') or '{}')
        conn = psycopg2.connect(host=DB_ENDPOINT, user=creds['username'], password=creds['password'], dbname=DB_NAME)
        conn.autocommit = False
        return conn
    except Exception as e:
        print('db connect failed', e)
        return None

def _parse_timestamp(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        except Exception:
            return None
    return None


def _sanitize_json_value(value):
    """Recursively strip NULL characters that PostgreSQL cannot accept."""
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, list):
        return [_sanitize_json_value(item) for item in value]
    if isinstance(value, dict):
        return {k: _sanitize_json_value(v) for k, v in value.items()}
    return value


def upsert_findings(conn, name, version, findings, score, label, metadata=None):
    cur = conn.cursor()
    metadata = metadata or {}
    completed_at = metadata.get('completed_at') or datetime.now(timezone.utc)
    queued_at = metadata.get('queued_at')
    if queued_at and isinstance(queued_at, str):
        queued_at = _parse_timestamp(queued_at)
    elif isinstance(queued_at, (int, float)):
        queued_at = datetime.fromtimestamp(float(queued_at), tz=timezone.utc)
    started_at = metadata.get('started_at')
    if started_at and isinstance(started_at, str):
        started_at = _parse_timestamp(started_at)
    elif isinstance(started_at, (int, float)):
        started_at = datetime.fromtimestamp(float(started_at), tz=timezone.utc)

    analyzer_version = metadata.get('analyzer_version') or os.environ.get('ANALYZER_VERSION')
    config_hash = metadata.get('config_hash')
    findings_s3_key = metadata.get('findings_s3_key')
    rerun_reason = metadata.get('rerun_reason')
    requested_by = metadata.get('requested_by')
    source = metadata.get('source')

    severity_counts = Counter()
    for f in findings:
        sev = (f.get('severity') or 'unknown').lower()
        severity_counts[sev] += 1
    high_count = severity_counts.get('high', 0)
    medium_count = severity_counts.get('medium', 0)
    low_count = severity_counts.get('low', 0)

    try:
        cur.execute("INSERT INTO packages(name, ecosystem, last_seen) VALUES(%s,'npm',now()) ON CONFLICT(name) DO UPDATE SET last_seen=EXCLUDED.last_seen RETURNING id", (name,))
        package_id = cur.fetchone()[0]
        package_author = _clean_text(metadata.get('package_author')) if metadata else None
        package_description = _clean_text(metadata.get('package_description')) if metadata else None
        if package_author is not None or package_description is not None:
            cur.execute(
                """
                UPDATE packages
                SET author = COALESCE(%s, author),
                    description = COALESCE(%s, description)
                WHERE id = %s
                """,
                (package_author, package_description, package_id),
            )
        cur.execute(
            """
            INSERT INTO versions(package_id, version, status, analyzed_at)
            VALUES(%s,%s,'analyzed', %s)
            ON CONFLICT(package_id, version) DO UPDATE
              SET status = EXCLUDED.status,
                  analyzed_at = EXCLUDED.analyzed_at
            RETURNING id
            """,
            (package_id, version, completed_at),
        )
        version_id = cur.fetchone()[0]
        cur.execute("DELETE FROM findings WHERE version_id = %s", (version_id,))
        for f in findings:
            details_raw = f.get('details') or {}
            details = _sanitize_json_value(details_raw)
            file_path = None
            if isinstance(details, dict):
                file_path = details.get('path')
            cur.execute(
                "INSERT INTO findings(version_id, rule, severity, details, file_path) VALUES(%s,%s,%s,%s,%s)",
                (version_id, f['rule'], f.get('severity'), json.dumps(details), file_path),
            )
        cur.execute("INSERT INTO scores(version_id, score, label) VALUES(%s,%s,%s) ON CONFLICT(version_id) DO UPDATE SET score=EXCLUDED.score, label=EXCLUDED.label", (version_id, score, label))
        cur.execute(
            """
            INSERT INTO scan_runs(
                version_id,
                source,
                queued_at,
                started_at,
                completed_at,
                analyzer_version,
                config_hash,
                score,
                label,
                high_count,
                medium_count,
                low_count,
                findings,
                findings_s3_key,
                rerun_reason,
                requested_by
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id
            """,
            (
                version_id,
                source,
                queued_at,
                started_at,
                completed_at,
                analyzer_version,
                config_hash,
                score,
                label,
                high_count,
                medium_count,
                low_count,
                Json(findings),
                findings_s3_key,
                rerun_reason,
                requested_by,
            ),
        )
        run_id = cur.fetchone()[0]
        conn.commit()
        return version_id, run_id
    except Exception as e:
        conn.rollback()
        print('db write failed', name, version, e)
        return None, None
    finally:
        cur.close()

def download_from_s3_to_tmp(name, version):
    if not S3_TARBALLS:
        return None
    s3 = boto3.client('s3', region_name=AWS_REGION)
    key = f"npm-raw-tarballs/{name}/{version}.tgz"
    tmp = Path(tempfile.mkdtemp(prefix='pkginferno-dl-')) / f"{name.replace('/', '__')}@{version}.tgz"
    s3.download_file(S3_TARBALLS, key, str(tmp))
    return str(tmp)

# ---------------------------
# Main
# ---------------------------
def main():
    cfg = load_config()
    scoring = load_scoring(cfg)
    analysis_cfg = cfg.get('analysis', {}) or {}
    # Build allowlist (from YAML or defaults)
    benign_list = analysis_cfg.get('allowlist', {}).get('build_tools', [])
    benign_patterns = benign_list if benign_list else DEFAULT_BENIGN_BUILD_TOOLS
    BENIGN_BUILD_RE = re.compile("|".join(benign_patterns), re.I)

    # Domain allowlist
    allow_domains = analysis_cfg.get('allow_domains', [
        "registry.npmjs.org","nodejs.org","github.com","raw.githubusercontent.com","objects.githubusercontent.com"
    ])
    flag_if_url_not_in_allowlist = analysis_cfg.get('flag_if_url_not_in_allowlist', True)
    if not flag_if_url_not_in_allowlist:
        allow_domains = []  # disable domain severity bump

    # YARA inline scanning (optional). When scan_mode is set to "worker",
    # this process skips YARA and expects dedicated yara_scanner workers.
    yara_cfg = analysis_cfg.get('yara', {}) or {}
    scan_mode = str(yara_cfg.get('scan_mode', 'per_file')).lower()
    inline_yara = yara_cfg.get('enabled', False) and scan_mode != 'worker'

    yara_rules = None
    if inline_yara:
        yara_rules = load_yara_rules(cfg)
        if not yara_rules:
            print("YARA requested but rules failed to load; continuing without inline YARA scanning")
            inline_yara = False
    elif yara_cfg.get('enabled', False) and scan_mode == 'worker':
        print("YARA configured for external workers; inline analyzer will skip YARA scans")

    yara_runtime_cfg = yara_cfg if inline_yara else {}

    # Extraction byte limit (0 or None = unlimited)
    max_extract_cfg = analysis_cfg.get('max_extract_bytes')
    try:
        max_extract_cfg = int(max_extract_cfg) if max_extract_cfg is not None else None
    except Exception:
        max_extract_cfg = None
    env_extract_limit = MAX_BYTES if MAX_BYTES > 0 else None
    effective_extract_limit = None
    if max_extract_cfg is not None:
        effective_extract_limit = max_extract_cfg if max_extract_cfg > 0 else None
    else:
        effective_extract_limit = env_extract_limit

    conn = get_db_conn()

    args = sys.argv[1:]
    if QUEUE_MODE == 'sqs' and SQS_ANALYZE_URL:
        sqs = boto3.client('sqs', region_name=AWS_REGION)
        print('consuming SQS analyze queue...')
        while True:
            try:
                resp = sqs.receive_message(QueueUrl=SQS_ANALYZE_URL, MaxNumberOfMessages=10, WaitTimeSeconds=10)
            except Exception as e:
                # Recover on connection resets
                print('analyze sqs warn', str(e))
                time.sleep(1)
                sqs = boto3.client('sqs', region_name=AWS_REGION)
                continue
            for m in resp.get('Messages', []):
                try:
                    rec = json.loads(m.get('Body') or '{}')
                    name = rec.get('name'); version = rec.get('version')
                    analysis_started = datetime.now(timezone.utc)
                    tgz_path = download_from_s3_to_tmp(name, version)
                    if tgz_path:
                        extracted_name, extracted_version, findings, package_meta = analyze_tgz(
                            tgz_path,
                            allow_domains,
                            BENIGN_BUILD_RE,
                            yara_rules,
                            yara_runtime_cfg,
                            effective_extract_limit,
                        )
                        actual_name = extracted_name or name
                        actual_version = extracted_version or version
                        s, label = score_findings(findings, scoring)
                        if conn and actual_name and actual_version:
                            metadata = {
                                'queued_at': rec.get('queued_at'),
                                'started_at': analysis_started,
                                'completed_at': datetime.now(timezone.utc),
                                'analyzer_version': os.environ.get('ANALYZER_VERSION'),
                                'config_hash': rec.get('config_hash'),
                                'findings_s3_key': rec.get('findings_s3_key'),
                                'rerun_reason': rec.get('rerun_reason'),
                                'requested_by': rec.get('requested_by'),
                                'source': rec.get('source') or 'analyzer',
                                'package_author': package_meta.get('author'),
                                'package_description': package_meta.get('description'),
                                'package_homepage': package_meta.get('homepage'),
                                'package_repository': package_meta.get('repository'),
                                'package_author_url': package_meta.get('author_url'),
                                'npm_publisher': package_meta.get('npm_username'),
                            }
                            upsert_findings(conn, actual_name, actual_version, findings, s, label, metadata=metadata)
                    try:
                        sqs.delete_message(QueueUrl=SQS_ANALYZE_URL, ReceiptHandle=m['ReceiptHandle'])
                    except Exception as e:
                        print('analyze sqs warn (delete)', str(e))
                        sqs = boto3.client('sqs', region_name=AWS_REGION)
                except Exception as e:
                    print('analyze sqs error', e)
    else:
        if not args:
            for p in Path(DOWNLOADS_DIR).glob('**/*.tgz'):
                name, version, findings, package_meta = analyze_tgz(
                    str(p),
                    allow_domains,
                    BENIGN_BUILD_RE,
                    yara_rules,
                    yara_runtime_cfg,
                    effective_extract_limit,
                )
                if findings:
                    s, label = score_findings(findings, scoring)
                    if conn and name and version:
                        upsert_findings(
                            conn,
                            name,
                            version,
                            findings,
                            s,
                            label,
                            metadata={
                                'package_author': package_meta.get('author'),
                                'package_description': package_meta.get('description'),
                                'package_homepage': package_meta.get('homepage'),
                                'package_repository': package_meta.get('repository'),
                                'package_author_url': package_meta.get('author_url'),
                                'npm_publisher': package_meta.get('npm_username'),
                            },
                        )
        else:
            for p in args:
                name, version, findings, package_meta = analyze_tgz(
                    p,
                    allow_domains,
                    BENIGN_BUILD_RE,
                    yara_rules,
                    yara_runtime_cfg,
                    effective_extract_limit,
                )
                if findings:
                    s, label = score_findings(findings, scoring)
                    if conn and name and version:
                        upsert_findings(
                            conn,
                            name,
                            version,
                            findings,
                            s,
                            label,
                            metadata={
                                'package_author': package_meta.get('author'),
                                'package_description': package_meta.get('description'),
                                'package_homepage': package_meta.get('homepage'),
                                'package_repository': package_meta.get('repository'),
                                'package_author_url': package_meta.get('author_url'),
                                'npm_publisher': package_meta.get('npm_username'),
                            },
                        )

if __name__ == '__main__':
    main()

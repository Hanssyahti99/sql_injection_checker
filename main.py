import argparse
import json
import logging
import re
import signal
import sys
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from typing import List, Set, Dict, Any, Optional, Tuple
import requests
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("SQLScope")

class Finding:
    def __init__(self, url: str, parameter: str, method: str, confidence: str, evidence: str):
        self.url = url
        self.parameter = parameter
        self.method = method
        self.confidence = confidence  # "Suspected" or "Higher-Confidence"
        self.evidence = evidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "confidence": self.confidence,
            "evidence": self.evidence
        }

class ScopeValidator:
    def __init__(self, base_url: str):
        parsed = urlparse(base_url)
        self.allowed_netloc = parsed.netloc
        self.allowed_scheme = parsed.scheme

    def is_in_scope(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return True
            return parsed.netloc.lower() == self.allowed_netloc.lower() and parsed.scheme in ("http", "https")
        except Exception:
            return False

    def normalize_url(self, url: str, base_url: str) -> Optional[str]:
        try:
            joined = urljoin(base_url, url)
            parsed = urlparse(joined)
            normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ''))
            if self.is_in_scope(normalized):
                return normalized
        except Exception:
            pass
        return None

class Crawler:
    def __init__(self, base_url: str, max_pages: int, max_depth: int, timeout: int, delay: float):
        self.base_url = base_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.delay = delay
        self.scope = ScopeValidator(base_url)
        self.discovered_urls: Set[str] = set()
        self.visited_urls: Set[str] = set()

    def discover(self) -> Set[str]:
        logger.info(f"Starting discovery on scope: {self.base_url}")
        self._parse_robots()
        self._parse_sitemap()
        self._check_openapi()

        queue: List[Tuple[str, int]] = [(self.base_url, 0)]
        self.discovered_urls.add(self.base_url)

        while queue and len(self.visited_urls) < self.max_pages:
            current_url, depth = queue.pop(0)
            if current_url in self.visited_urls or depth > self.max_depth:
                continue
            
            self.visited_urls.add(current_url)
            time.sleep(self.delay)

            try:
                resp = requests.get(current_url, timeout=self.timeout, headers={"User-Agent": "SQLScope/1.0"}, allow_redirects=True)
                if not self.scope.is_in_scope(resp.url):
                    continue
                
                if "text/html" in resp.headers.get("Content-Type", ""):
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for a_tag in soup.find_all("a", href=True):
                        norm = self.scope.normalize_url(a_tag['href'], current_url)
                        if norm and norm not in self.discovered_urls:
                            self.discovered_urls.add(norm)
                            if depth + 1 <= self.max_depth and len(self.discovered_urls) < self.max_pages:
                                queue.append((norm, depth + 1))
            except Exception as e:
                logger.debug(f"Error crawling {current_url}: {e}")

        logger.info(f"Discovery complete. Found {len(self.discovered_urls)} endpoints.")
        return self.discovered_urls

    def _parse_robots(self):
        robots_url = urljoin(self.base_url, "/robots.txt")
        try:
            resp = requests.get(robots_url, timeout=self.timeout, headers={"User-Agent": "SQLScope/1.0"})
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    if line.lower().startswith("allow:") or line.lower().startswith("disallow:") or line.lower().startswith("sitemap:"):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            val = parts[1].strip()
                            if val.startswith("/") or val.startswith("http"):
                                norm = self.scope.normalize_url(val, self.base_url)
                                if norm:
                                    self.discovered_urls.add(norm)
        except Exception:
            pass

    def _parse_sitemap(self):
        sitemap_url = urljoin(self.base_url, "/sitemap.xml")
        try:
            resp = requests.get(sitemap_url, timeout=self.timeout, headers={"User-Agent": "SQLScope/1.0"})
            if resp.status_code == 200 and "xml" in resp.headers.get("Content-Type", ""):
                root = ET.fromstring(resp.content)
                for elem in root.iter():
                    if elem.tag.endswith("loc"):
                        if elem.text:
                            norm = self.scope.normalize_url(elem.text.strip(), self.base_url)
                            if norm:
                                self.discovered_urls.add(norm)
        except Exception:
            pass

    def _check_openapi(self):
        common_paths = ["/swagger.json", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json"]
        for path in common_paths:
            url = urljoin(self.base_url, path)
            try:
                resp = requests.get(url, timeout=self.timeout, headers={"User-Agent": "SQLScope/1.0"})
                if resp.status_code == 200 and "json" in resp.headers.get("Content-Type", ""):
                    data = resp.json()
                    if "paths" in data:
                        for p in data["paths"].keys():
                            norm = self.scope.normalize_url(p, self.base_url)
                            if norm:
                                self.discovered_urls.add(norm)
            except Exception:
                pass

class SQLiScanner:
    ERROR_SIGNATURES = [
        "sql syntax", "syntax error", "unclosed quotation mark", 
        "unterminated string literal", "mysql_fetch", "pdoException",
        "sqlite3.OperationalError", "pg_query", "ORA-", "Microsoft OLE DB Provider",
        "ODBC SQL Server Driver", "SQLServer JDBC Driver"
    ]

    def __init__(self, timeout: int, delay: float):
        self.timeout = timeout
        self.delay = delay

    def test_endpoints(self, urls: Set[str]) -> List[Finding]:
        findings: List[Finding] = []
        logger.info("Starting SQL Injection checks...")

        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue

            for param in params.keys():
                time.sleep(self.delay)
                finding = self._test_parameter(url, param, params)
                if finding:
                    findings.append(finding)

        return findings

    def _test_parameter(self, url: str, target_param: str, original_params: Dict[str, List[str]]) -> Optional[Finding]:
        parsed = urlparse(url)
        
        try:
            base_resp = requests.get(url, timeout=self.timeout, headers={"User-Agent": "SQLScope/1.0"})
        except Exception:
            return None

        # Test 1: Error-based check with single quote
        test_params = {k: v[0] for k, v in original_params.items()}
        test_params[target_param] = test_params[target_param] + "'"
        
        query_str = urlencode(test_params)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_str, ''))

        try:
            err_resp = requests.get(test_url, timeout=self.timeout, headers={"User-Agent": "SQLScope/1.0"})
            for sig in self.ERROR_SIGNATURES:
                if sig.lower() in err_resp.text.lower() and sig.lower() not in base_resp.text.lower():
                    return Finding(
                        url=url,
                        parameter=target_param,
                        method="Error-Based (Single Quote)",
                        confidence="Higher-Confidence",
                        evidence=f"Matched error signature: '{sig}'"
                    )
        except Exception:
            pass

        # Test 2: Boolean-based differential check
        try:
            bool_true_params = {k: v[0] for k, v in original_params.items()}
            bool_true_params[target_param] = bool_true_params[target_param] + " AND 1=1"
            url_true = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(bool_true_params), ''))
            
            bool_false_params = {k: v[0] for k, v in original_params.items()}
            bool_false_params[target_param] = bool_false_params[target_param] + " AND 1=2"
            url_false = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(bool_false_params), ''))

            resp_true = requests.get(url_true, timeout=self.timeout, headers={"User-Agent": "SQLScope/1.0"})
            resp_false = requests.get(url_false, timeout=self.timeout, headers={"User-Agent": "SQLScope/1.0"})

            if resp_true.status_code == base_resp.status_code and resp_false.status_code != base_resp.status_code:
                return Finding(
                    url=url,
                    parameter=target_param,
                    method="Boolean-Based Differential",
                    confidence="Suspected",
                    evidence=f"Status code variance: True={resp_true.status_code}, False={resp_false.status_code}, Base={base_resp.status_code}"
                )
        except Exception:
            pass

        return None

class Reporter:
    @staticmethod
    def report(findings: List[Finding], discovered_count: int, tested_count: int, output_file: Optional[str]):
        print("\n" + "="*50)
        print("                SQLScope Scan Report                ")
        print("="*50)
        print(f"Discovered Endpoints : {discovered_count}")
        print(f"Tested Endpoints     : {tested_count}")
        print(f"Total Findings       : {len(findings)}")
        print("-" * 50)

        for i, f in enumerate(findings, 1):
            print(f"[{i}] URL        : {f.url}")
            print(f"    Parameter  : {f.parameter}")
            print(f"    Method     : {f.method}")
            print(f"    Confidence : {f.confidence}")
            print(f"    Evidence   : {f.evidence}")
            print("-" * 30)

        print("\n[Remediation Recommendation]")
        print("- Use parameterized queries (Prepared Statements) for all database operations.")
        print("- Avoid direct concatenation of user input into SQL commands.")
        print("- Implement strict input validation and type casting.")
        print("="*50)

        if output_file:
            report_data = {
                "discovered_count": discovered_count,
                "tested_count": tested_count,
                "findings": [f.to_dict() for f in findings]
            }
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(report_data, f, indent=2)
                logger.info(f"JSON report successfully saved to {output_file}")
            except Exception as e:
                logger.error(f"Failed to save JSON report: {e}")

def signal_handler(sig, frame):
    print("\n[!] Scan interrupted by user. Exiting safely...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="SQLScope - SQL Injection Vulnerability Assessment Tool")
    parser.add_argument("--url", required=True, help="Target URL (e.g., http://example.com)")
    parser.add_argument("--max-pages", type=int, default=30, help="Maximum pages to crawl")
    parser.add_argument("--depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--output", help="Path to save JSON report (e.g., report.json)")

    args = parser.parse_args()

    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        logger.error("Target URL must start with http:// or https://")
        sys.exit(1)

    crawler = Crawler(
        base_url=args.url,
        max_pages=args.max_pages,
        max_depth=args.depth,
        timeout=args.timeout,
        delay=args.delay
    )
    discovered = crawler.discover()

    endpoints_with_params = [u for u in discovered if urlparse(u).query]
    
    scanner = SQLiScanner(timeout=args.timeout, delay=args.delay)
    findings = scanner.test_endpoints(set(endpoints_with_params))

    Reporter.report(
        findings=findings,
        discovered_count=len(discovered),
        tested_count=len(endpoints_with_params),
        output_file=args.output
    )

if __name__ == "__main__":
    main()
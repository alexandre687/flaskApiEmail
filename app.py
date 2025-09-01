import os
import re
import ssl
import time
import json
import csv
import socket
import random
import smtplib
import threading
from collections import deque, defaultdict
from urllib.parse import urljoin, urlparse

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

import requests
from bs4 import BeautifulSoup
import dns.resolver
import tldextract
from pypdf import PdfReader

# ----------------------- Config (env overrides) -----------------------
USER_AGENT        = os.getenv("USER_AGENT", "Mozilla/5.0 (Email-Finder/1.3)")
MAX_PAGES         = int(os.getenv("MAX_PAGES", "60"))
REQUEST_TIMEOUT   = int(os.getenv("REQUEST_TIMEOUT", "12"))
CRAWL_DELAY_SEC   = float(os.getenv("CRAWL_DELAY_SEC", "0.25"))
SMTP_TIMEOUT      = int(os.getenv("SMTP_TIMEOUT", "10"))
SMTP_FROM         = os.getenv("SMTP_FROM", "check@example.com")
HELO_DOMAIN       = os.getenv("HELO_DOMAIN", "example.com")
SAVE_JSON_PATH    = os.getenv("SAVE_JSON_PATH", "emails_resultados.json")
SAVE_CSV_PATH     = os.getenv("SAVE_CSV_PATH", "emails_resultados.csv")
SAVE_VALID_CSV    = os.getenv("SAVE_VALID_CSV", "emails_validos.csv")
ALLOW_FILE_SAVE   = os.getenv("ALLOW_FILE_SAVE", "true").lower() in ("1","true","yes")
# ---------------------------------------------------------------------

EMAIL_REGEX = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', re.I)

def log(msg):
    print(f"[LOG] {msg}", flush=True)

def normalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = urlparse(d).netloc
    return d

def etld1(host: str) -> str:
    ext = tldextract.extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

def same_registrable(url: str, base_host: str) -> bool:
    try:
        host = urlparse(url).netloc or base_host
        return etld1(host) == etld1(base_host)
    except Exception:
        return False

def fetch(url: str, timeout=REQUEST_TIMEOUT):
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT}, allow_redirects=True)
        ct = (resp.headers.get("content-type") or "").lower()
        if resp.status_code == 200:
            return resp.content, ct
    except requests.RequestException:
        pass
    return b"", ""

def extract_cfemail(hex_str: str) -> str:
    try:
        data = bytes.fromhex(hex_str)
        key = data[0]
        decoded = ''.join(chr(b ^ key) for b in data[1:])
        return decoded
    except Exception:
        return ""

def extract_emails_from_html(html_bytes: bytes, base_url: str, target_domain: str):
    emails = set()
    try:
        html = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        html = str(html_bytes)

    for m in EMAIL_REGEX.findall(html):
        if m.lower().endswith("@" + target_domain):
            emails.add(m)

    soup = BeautifulSoup(html, "html.parser")

    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.lower().startswith("mailto:"):
            addr = href.split(":", 1)[1].split("?")[0]
            if addr.lower().endswith("@" + target_domain):
                emails.add(addr)

    for el in soup.select("a.__cf_email__"):
        cf = el.get("data-cfemail")
        if cf:
            decoded = extract_cfemail(cf)
            if decoded.lower().endswith("@" + target_domain):
                emails.add(decoded)

    return emails

def extract_emails_from_pdf(pdf_bytes: bytes, target_domain: str):
    emails = set()
    try:
        from io import BytesIO
        reader = PdfReader(BytesIO(pdf_bytes))
        for page in reader.pages:
            txt = page.extract_text() or ""
            for m in EMAIL_REGEX.findall(txt):
                if m.lower().endswith("@" + target_domain):
                    emails.add(m)
    except Exception:
        pass
    return emails

def parse_links_from_html(html_bytes: bytes, url: str):
    links = set()
    try:
        html = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        html = str(html_bytes)
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        try:
            links.add(urljoin(url, a["href"]))
        except Exception:
            continue
    return links

def try_urls_for_domain(domain: str):
    host = normalize_domain(domain)
    candidates = [
        f"https://{host}/",
        f"http://{host}/",
        f"https://www.{host}/",
        f"http://www.{host}/",
    ]
    seen = set()
    final = []
    for u in candidates:
        h = urlparse(u).netloc
        if h not in seen:
            seen.add(h)
            final.append(u)
    return final

def discover_from_sitemap(base_host: str):
    urls = set()
    for root in [f"https://{base_host}", f"http://{base_host}", f"https://www.{base_host}", f"http://www.{base_host}"]:
        sm = urljoin(root, "/sitemap.xml")
        content, ct = fetch(sm)
        if content and "xml" in ct:
            try:
                soup = BeautifulSoup(content, "xml")
                for loc in soup.find_all("loc"):
                    if loc.text:
                        urls.add(loc.text.strip())
            except Exception:
                continue
    return list(urls)

def crawl_for_emails(domain: str, max_pages=MAX_PAGES):
    target_domain = normalize_domain(domain)
    seeds = try_urls_for_domain(target_domain)

    COMMON_PATHS = ["/", "/contato", "/contact", "/about", "/equipe", "/time", "/press", "/blog", "/imprensa", "/quem-somos"]
    for base in list(seeds):
        for p in COMMON_PATHS:
            seeds.append(urljoin(base, p))

    sitemap_urls = discover_from_sitemap(target_domain)
    seeds.extend(sitemap_urls)

    q = deque()
    visited = set()
    emails = set()
    sources_map = defaultdict(set)

    for s in seeds:
        q.append(s)

    while q and len(visited) < max_pages:
        url = q.popleft()
        if url in visited:
            continue
        visited.add(url)

        if not same_registrable(url, target_domain):
            continue

        content, ct = fetch(url)
        if not content:
            continue

        page_emails = set()
        if "pdf" in ct or url.lower().endswith(".pdf"):
            page_emails = extract_emails_from_pdf(content, target_domain)
        else:
            page_emails = extract_emails_from_html(content, url, target_domain)
            links = parse_links_from_html(content, url)
            for l in links:
                if l not in visited and same_registrable(l, target_domain) and len(visited) + len(q) < max_pages:
                    q.append(l)

        if page_emails:
            emails |= page_emails
            for e in page_emails:
                sources_map[e].add(url)

        time.sleep(CRAWL_DELAY_SEC)

    return emails, sources_map

def mx_lookup(domain: str):
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=6.0)
        hosts = [str(r.exchange).rstrip('.') for r in sorted(answers, key=lambda r: r.preference)]
        return hosts
    except Exception:
        return []

def smtp_rcpt_check(email: str, mx_host: str):
    try:
        with smtplib.SMTP(mx_host, 25, timeout=SMTP_TIMEOUT) as smtp:
            smtp.ehlo(HELO_DOMAIN)
            try:
                if smtp.has_extn('starttls'):
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo(HELO_DOMAIN)
            except smtplib.SMTPException:
                pass
            smtp.mail(SMTP_FROM)
            code, _ = smtp.rcpt(email)
            return code
    except (socket.timeout, smtplib.SMTPException, OSError):
        return None

def is_catch_all(domain: str, mx_hosts: list[str]) -> bool:
    local = ''.join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))
    probe = f"{local}@{domain}"
    for mx in mx_hosts[:2]:
        code = smtp_rcpt_check(probe, mx)
        if code and 200 <= code < 300:
            return True
    return False

def verify_all_statuses(domain: str, candidates: set[str]):
    d = normalize_domain(domain)
    mx_hosts = mx_lookup(d)
    if not mx_hosts:
        log("Sem MX — não dá pra verificar via SMTP.")
        return [], {"reason": "no_mx", "mx_hosts": []}

    catch_all = is_catch_all(d, mx_hosts)
    if catch_all:
        log("Servidor parece CATCH-ALL (aceita qualquer destinatário).")

    results = []
    lock = threading.Lock()

    def worker(email):
        status = "unknown"
        code_final = None
        mx_used = None
        for mx in mx_hosts:
            code = smtp_rcpt_check(email, mx)
            if code is None:
                continue
            code_final = code
            mx_used = mx
            if 200 <= code < 300:
                status = "valid"
                break
            elif code in (450, 451, 452, 421):
                status = "risky"
            elif code in (550, 551, 552, 553, 554):
                status = "invalid"
                break
        with lock:
            results.append({
                "email": email,
                "status": status,
                "mx": mx_used,
                "code": code_final
            })

    threads = []
    for e in candidates:
        t = threading.Thread(target=worker, args=(e,))
        t.start()
        threads.append(t)
        time.sleep(0.05)

    for t in threads:
        t.join()

    summary = {
        "valid":   sum(1 for r in results if r["status"] == "valid"),
        "risky":   sum(1 for r in results if r["status"] == "risky"),
        "invalid": sum(1 for r in results if r["status"] == "invalid"),
        "unknown": sum(1 for r in results if r["status"] == "unknown"),
    }
    debug = {"mx_hosts": mx_hosts, "catch_all": catch_all, "summary": summary}
    return results, debug

def save_outputs_json_csv(rows, json_path=SAVE_JSON_PATH, csv_path=SAVE_CSV_PATH):
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(rows, jf, ensure_ascii=False, indent=2)

    fieldnames = ["email", "status", "source_count", "sources", "mx", "code"]
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        w = csv.DictWriter(cf, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            sources = r.get("sources", [])
            w.writerow({
                "email": r.get("email",""),
                "status": r.get("status",""),
                "source_count": len(sources) if isinstance(sources, (list, set, tuple)) else 0,
                "sources": ";".join(sorted(sources)) if isinstance(sources, (list, set, tuple)) else "",
                "mx": r.get("mx","") or "",
                "code": r.get("code","") if r.get("code") is not None else ""
            })
    log(f"Arquivos salvos: {json_path} e {csv_path}")

def run(domain: str, max_pages: int = MAX_PAGES, save_files: bool = ALLOW_FILE_SAVE):
    d = normalize_domain(domain)
    log(f"Coletando e-mails públicos em {d} ...")
    public_emails, sources_map = crawl_for_emails(d, max_pages=max_pages)
    log(f"Encontrados (públicos): {len(public_emails)}")

    if not public_emails:
        log("Nenhum e-mail público visível.")
        if save_files:
            save_outputs_json_csv([], SAVE_JSON_PATH, SAVE_CSV_PATH)
        return {"domain": d, "results": [], "debug": {"note": "no_public_emails"}}

    log("Verificando via MX/SMTP (todos os status)...")
    verified_rows, debug = verify_all_statuses(d, public_emails)

    for r in verified_rows:
        r["sources"] = sorted(sources_map.get(r["email"], []))

    if save_files:
        save_outputs_json_csv(verified_rows, SAVE_JSON_PATH, SAVE_CSV_PATH)
        valid_only = [r["email"] for r in verified_rows if r["status"] == "valid"]
        if valid_only:
            with open(SAVE_VALID_CSV, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["email"])
                for e in sorted(valid_only):
                    w.writerow([e])

    return {"domain": d, "results": verified_rows, "debug": debug}

# ------------------------ Flask App ------------------------
app = Flask(__name__)
# Ative CORS se você for chamar do n8n/front-end
if os.getenv("ENABLE_CORS", "true").lower() in ("1","true","yes"):
    CORS(app)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

@app.route("/run", methods=["POST"])
def run_endpoint():
    """
    Body JSON:
    {
      "domain": "exemplo.com",
      "max_pages": 60,          (opcional)
      "save_files": true,       (opcional; respeita ALLOW_FILE_SAVE)
      "download": null|"json"|"csv"|"valid_csv"  (opcional)
    }
    """
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "Campo 'domain' é obrigatório."}), 400

    max_pages = int(data.get("max_pages") or MAX_PAGES)
    save_files = bool(data.get("save_files") if "save_files" in data else ALLOW_FILE_SAVE)
    download = data.get("download")

    try:
        result = run(domain, max_pages=max_pages, save_files=save_files)
    except Exception as e:
        log(f"Erro em run(): {e}")
        return jsonify({"error": "processing_error", "detail": str(e)}), 500

    # entrega de arquivos (opcional)
    if download:
        if download == "json" and os.path.exists(SAVE_JSON_PATH):
            return send_file(SAVE_JSON_PATH, as_attachment=True)
        if download == "csv" and os.path.exists(SAVE_CSV_PATH):
            return send_file(SAVE_CSV_PATH, as_attachment=True)
        if download == "valid_csv" and os.path.exists(SAVE_VALID_CSV):
            return send_file(SAVE_VALID_CSV, as_attachment=True)
        return jsonify({"error": "file_not_found_or_download_param_invalid"}), 404

    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "80")))

import asyncio
import aiohttp
import re
import os
from urllib.parse import urljoin, urlparse
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from fpdf import FPDF
from bs4 import BeautifulSoup
from datetime import datetime

BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"

# ─── Vulnerability Checks ───────────────────────────────────────────

async def check_sql_injection(session: aiohttp.ClientSession, url: str) -> list:
    findings = []
    payloads = ["'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\""]
    test_url = url + "?id="
    for payload in payloads:
        try:
            async with session.get(test_url + payload, timeout=aiohttp.ClientTimeout(total=8)) as r:
                text = await r.text()
                errors = ["sql syntax", "mysql_fetch", "ORA-", "pg_query",
                         "sqlite3", "syntax error", "unclosed quotation"]
                for err in errors:
                    if err.lower() in text.lower():
                        findings.append(f"[SQLi] Payload `{payload}` triggered: `{err}`")
                        break
        except Exception:
            pass
    return findings

async def check_xss(session: aiohttp.ClientSession, url: str) -> list:
    findings = []
    payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><svg onload=alert(1)>"
    ]
    test_url = url + "?q="
    for payload in payloads:
        try:
            async with session.get(test_url + payload, timeout=aiohttp.ClientTimeout(total=8)) as r:
                text = await r.text()
                if payload in text:
                    findings.append(f"[XSS] Reflected payload found: `{payload[:40]}`")
        except Exception:
            pass
    return findings

async def check_exposed_files(session: aiohttp.ClientSession, base_url: str) -> list:
    findings = []
    sensitive_paths = [
        ".env", ".git/config", "config.php", "wp-config.php",
        "phpinfo.php", "admin/", "backup.sql", "database.sql",
        "robots.txt", "sitemap.xml", ".htaccess", "web.config",
        "debug.log", "error.log", "composer.json", "package.json",
        "README.md", ".DS_Store", "Thumbs.db", "config.yaml",
        "config.yml", ".gitignore", "install.php", "setup.php"
    ]
    for path in sensitive_paths:
        target = urljoin(base_url.rstrip("/") + "/", path)
        try:
            async with session.get(target, timeout=aiohttp.ClientTimeout(total=6)) as r:
                if r.status == 200:
                    size = len(await r.read())
                    findings.append(f"[EXPOSED] {target} → HTTP 200 ({size} bytes)")
        except Exception:
            pass
    return findings

async def check_headers(session: aiohttp.ClientSession, url: str) -> list:
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
            headers = dict(r.headers)
            security_headers = {
                "X-Frame-Options": "Clickjacking protection missing",
                "X-Content-Type-Options": "MIME sniffing protection missing",
                "Content-Security-Policy": "CSP header missing",
                "Strict-Transport-Security": "HSTS missing",
                "X-XSS-Protection": "XSS protection header missing",
                "Referrer-Policy": "Referrer policy missing"
            }
            for header, message in security_headers.items():
                if header not in headers:
                    findings.append(f"[HEADER] {message}: `{header}`")

            if "Server" in headers:
                findings.append(f"[INFO LEAK] Server header exposed: `{headers['Server']}`")
            if "X-Powered-By" in headers:
                findings.append(f"[INFO LEAK] X-Powered-By exposed: `{headers['X-Powered-By']}`")
    except Exception as e:
        findings.append(f"[ERROR] Header check failed: {e}")
    return findings

async def check_directory_listing(session: aiohttp.ClientSession, base_url: str) -> list:
    findings = []
    dirs = ["images/", "uploads/", "files/", "assets/", "backup/", "logs/", "tmp/"]
    for d in dirs:
        target = urljoin(base_url.rstrip("/") + "/", d)
        try:
            async with session.get(target, timeout=aiohttp.ClientTimeout(total=6)) as r:
                if r.status == 200:
                    text = await r.text()
                    if "index of" in text.lower() or "parent directory" in text.lower():
                        findings.append(f"[DIR LISTING] Directory open: {target}")
        except Exception:
            pass
    return findings

async def download_accessible_data(session: aiohttp.ClientSession, url: str) -> dict:
    """Attempt to download any exposed sensitive content"""
    downloaded = {}
    # এখানে আপনার ইচ্ছামতো ফাইলের নাম বা পাথ যুক্ত করতে পারেন
    targets = [".env", "robots.txt", "sitemap.xml", ".gitignore",
               "composer.json", "package.json", "README.md", "debug.log", "error.log"]

    for path in targets:
        target = urljoin(url.rstrip("/") + "/", path)
        try:
            async with session.get(target, timeout=aiohttp.ClientTimeout(total=6)) as r:
                if r.status == 200:
                    content = await r.text()
                    if len(content) > 0 and len(content) < 50000:
                        downloaded[path] = content[:2000]  # ২ কিলোবাইট পর্যন্ত প্রিভিউ
        except Exception:
            pass
    return downloaded

# ─── PDF Report Generator ───────────────────────────────────────────

def generate_pdf_report(url: str, all_findings: dict, downloaded: dict) -> str:
    pdf = FPDF()
    pdf.add_page()

    # Header
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Security Audit Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Target: {url}", ln=True, align="C")
    pdf.cell(0, 8, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
    pdf.ln(5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)

    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}

    severity_map = {
        "SQLi": "CRITICAL", "XSS": "HIGH", "EXPOSED": "HIGH",
        "DIR LISTING": "HIGH", "HEADER": "MEDIUM", "INFO LEAK": "MEDIUM",
        "ERROR": "INFO"
    }

    # Findings by category
    for category, findings in all_findings.items():
        if not findings:
            continue
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(0, 8, f"  {category}", ln=True, fill=True)
        pdf.set_font("Helvetica", "", 9)

        for finding in findings:
            sev = "INFO"
            for key, s in severity_map.items():
                if f"[{key}]" in finding:
                    sev = s
                    severity_count[s] += 1
                    break

            color = {"CRITICAL": (200,0,0), "HIGH": (220,100,0),
                    "MEDIUM": (200,180,0), "INFO": (100,100,100)}[sev]
            pdf.set_text_color(*color)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(20, 6, f"[{sev}]")
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 8)

            safe_finding = finding.encode("latin-1", "replace").decode("latin-1")
            pdf.multi_cell(0, 6, f" {safe_finding}")
        pdf.ln(3)

    # Summary box
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Summary", ln=True)
    pdf.set_font("Helvetica", "", 10)
    total = sum(severity_count.values())
    for sev, count in severity_count.items():
        if count > 0:
            pdf.cell(0, 7, f"  {sev}: {count}", ln=True)
    pdf.cell(0, 7, f"  Total Issues: {total}", ln=True)

    # Downloaded content
    if downloaded:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Downloaded Accessible Files", ln=True)
        pdf.set_fill_color(230, 230, 230)
        pdf.ln(3)

        for filename, content in downloaded.items():
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, f"  File: {filename}", ln=True, fill=True)
            pdf.set_font("Courier", "", 7)
            safe_content = content.encode("latin-1", "replace").decode("latin-1")
            pdf.multi_cell(0, 5, safe_content[:1500])
            pdf.ln(3)

    path = f"/tmp/audit_{urlparse(url).netloc}_{datetime.now().strftime('%H%M%S')}.pdf"
    pdf.output(path)
    return path

# ─── Bot Handlers ────────────────────────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🔍 *Security Audit Bot*\n\n"
        "Commands:\n"
        "`/scan <url>` — Full vulnerability scan + PDF report\n"
        "`/headers <url>` — Check security headers only\n"
        "`/exposed <url>` — Check exposed files only\n\n"
        "Example: `/scan https://yoursite.com`",
        parse_mode="Markdown"
    )

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: `/scan https://yoursite.com`", parse_mode="Markdown")
        return

    url = context.args[0].strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    msg = await update.message.reply_text(
        f"🔄 Scanning `{url}`...\nThis may take 30-60 seconds.",
        parse_mode="Markdown"
    )

    try:
        async with aiohttp.ClientSession(
            headers={"User-Agent": "Mozilla/5.0 SecurityAuditBot/1.0"},
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            await msg.edit_text("🔄 Checking headers...")
            headers_findings = await check_headers(session, url)

            await msg.edit_text("🔄 Testing SQLi vectors...")
            sqli_findings = await check_sql_injection(session, url)

            await msg.edit_text("🔄 Testing XSS vectors...")
            xss_findings = await check_xss(session, url)

            await msg.edit_text("🔄 Scanning exposed files...")
            exposed_findings = await check_exposed_files(session, url)

            await msg.edit_text("🔄 Checking directory listings...")
            dir_findings = await check_directory_listing(session, url)

            await msg.edit_text("🔄 Attempting data download...")
            downloaded = await download_accessible_data(session, url)

        all_findings = {
            "HTTP Security Headers": headers_findings,
            "SQL Injection": sqli_findings,
            "Cross-Site Scripting (XSS)": xss_findings,
            "Exposed Sensitive Files": exposed_findings,
            "Directory Listing": dir_findings
        }

        total = sum(len(v) for v in all_findings.values())

        await msg.edit_text("🔄 Generating PDF report...")
        pdf_path = generate_pdf_report(url, all_findings, downloaded)

        summary = f"✅ *Scan Complete* — `{url}`\n\n"
        summary += f"Total issues found: *{total}*\n"
        if downloaded:
            summary += f"Files downloaded: *{len(downloaded)}* ({', '.join(downloaded.keys())})\n"
        summary += "\n📄 Full report attached below."

        await msg.edit_text(summary, parse_mode="Markdown")

        with open(pdf_path, "rb") as f:
            await update.message.reply_document(
                document=f,
                filename=f"audit_{urlparse(url).netloc}.pdf",
                caption=f"Security audit report for {url}"
            )
        os.remove(pdf_path)

    except Exception as e:
        await msg.edit_text(f"❌ Scan failed: `{str(e)}`", parse_mode="Markdown")

async def headers_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: `/headers https://yoursite.com`", parse_mode="Markdown")
        return
    url = context.args[0].strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        findings = await check_headers(session, url)

    if findings:
        text = "🔍 *Header Issues:*\n\n" + "\n".join(f"• {f}" for f in findings)
    else:
        text = "✅ All security headers present."
    await update.message.reply_text(text, parse_mode="Markdown")

async def exposed_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: `/exposed https://yoursite.com`", parse_mode="Markdown")
        return
    url = context.args[0].strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
        findings = await check_exposed_files(session, url)

    if findings:
        text = "⚠️ *Exposed Files:*\n\n" + "\n".join(f"• {f}" for f in findings)
    else:
        text = "✅ No obviously exposed files found."
    await update.message.reply_text(text, parse_mode="Markdown")

# ─── Main ────────────────────────────────────────────────────────────

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CommandHandler("headers", headers_command))
    app.add_handler(CommandHandler("exposed", exposed_command))
    print("Bot running...")
    app.run_polling()

if __name__ == "__main__":
    main()

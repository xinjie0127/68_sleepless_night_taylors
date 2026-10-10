"""Generate a realistic sample penetration testing report PDF for FixFlow AI."""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

OUTPUT = r"C:\Users\asus\WorkBuddy AI\2026-10-10-11-41-57\fixflow-ai\sample-data\acme-pentest-report.pdf"

styles = getSampleStyleSheet()

# Custom styles
cover_title = ParagraphStyle('CoverTitle', parent=styles['Title'],
    fontSize=28, alignment=TA_CENTER, spaceAfter=6, textColor=HexColor('#1a1a2e'))
cover_sub = ParagraphStyle('CoverSub', parent=styles['Normal'],
    fontSize=14, alignment=TA_CENTER, textColor=HexColor('#555555'), spaceAfter=4)
h1 = ParagraphStyle('H1', parent=styles['Heading1'],
    fontSize=18, spaceAfter=10, spaceBefore=20, textColor=HexColor('#1a1a2e'))
h2 = ParagraphStyle('H2', parent=styles['Heading2'],
    fontSize=14, spaceAfter=6, spaceBefore=14, textColor=HexColor('#2d2d44'))
body = ParagraphStyle('Body', parent=styles['Normal'],
    fontSize=10, leading=14, spaceAfter=6)
finding_title = ParagraphStyle('FindingTitle', parent=styles['Heading2'],
    fontSize=12, spaceAfter=4, spaceBefore=12, textColor=HexColor('#1a1a2e'))
label_style = ParagraphStyle('Label', parent=styles['Normal'],
    fontSize=9, textColor=HexColor('#888888'), spaceAfter=2)

SEV_COLORS = {
    'Critical': HexColor('#f85149'),
    'High': HexColor('#db6d28'),
    'Medium': HexColor('#d29922'),
    'Low': HexColor('#8b949e'),
}

FINDINGS = [
    {
        'id': 'F-001',
        'title': 'Remote Code Execution via Path Traversal in nginx Upload Module',
        'severity': 'Critical',
        'cvss': '9.8',
        'asset': 'web-prod-01.web.acme.local',
        'asset_type': 'Web Server',
        'exposure': 'Internet-facing',
        'cve': 'N/A',
        'description': 'The legacy upload module on the public-facing nginx server allows path traversal via specially crafted multipart form data. An unauthenticated attacker can traverse directory structures and upload a web shell to the webroot, achieving remote code execution as the nginx worker user. A public exploit for this configuration is available.',
        'impact': 'Full system compromise of the primary web server. Attacker can read/modify all web content, pivot to internal network, and potentially access the backend database containing customer PII.',
        'recommendation': '1. Immediately disable the legacy upload module in nginx.conf.\n2. Upgrade nginx to version 1.27.x which removes the vulnerable code path.\n3. Implement a WAF rule to block path traversal patterns in multipart form data.\n4. Rotate all SSL certificates and API keys stored on the server.\n5. Conduct a forensic review of access logs for indicators of compromise.',
    },
    {
        'id': 'F-002',
        'title': 'SQL Injection in Customer Portal Login Endpoint',
        'severity': 'Critical',
        'cvss': '9.1',
        'asset': 'customer-portal.app.acme.local',
        'asset_type': 'Web Application',
        'exposure': 'Internet-facing',
        'cve': 'CVE-2024-3120',
        'description': 'The login.do endpoint accepts a user parameter that is concatenated directly into a SQL query without parameterization. Boolean-based blind SQL injection was confirmed by extracting the database version string through time-delay techniques. The backend database is MySQL 8.0.',
        'impact': 'Attacker can dump the entire customer database including credentials (stored as MD5 hashes), personal information, and order history. This constitutes a PII breach under GDPR.',
        'recommendation': '1. Replace all dynamic SQL with parameterized prepared statements.\n2. Rotate all database credentials immediately.\n3. Implement input validation using an allowlist approach.\n4. Deploy a WAF with SQL injection detection rules.\n5. Force password reset for all users due to potential credential exposure.',
    },
    {
        'id': 'F-003',
        'title': 'Outdated TLS Configuration on Payment Gateway',
        'severity': 'High',
        'cvss': '7.5',
        'asset': 'payments.acme.local',
        'asset_type': 'Application',
        'exposure': 'Internet-facing',
        'cve': 'N/A',
        'description': 'The payment gateway accepts TLS 1.0 and TLS 1.1 connections. These protocols have known cryptographic weaknesses and are prohibited under PCI DSS 3.2.1 Requirement 4.1. The server also accepts weak cipher suites including RC4 and 3DES.',
        'impact': 'PCI DSS non-compliance. Risk of decryption attacks on payment traffic. Potential fines from acquiring bank and card brands.',
        'recommendation': '1. Update nginx configuration to enforce TLS 1.2 minimum (preferably 1.3).\n2. Remove weak cipher suites (RC4, 3DES, CBC mode ciphers).\n3. Enable HSTS with a minimum age of 6 months.\n4. Request a PCI ASV re-scan to verify compliance.\n5. Update the security configuration baseline document.',
    },
    {
        'id': 'F-004',
        'title': 'Missing Multi-Factor Authentication on Admin VPN',
        'severity': 'Critical',
        'cvss': '9.0',
        'asset': 'vpn.acme.local',
        'asset_type': 'Network',
        'exposure': 'Internet-facing',
        'cve': 'N/A',
        'description': 'The SSL VPN admin console permits remote login using only username and password credentials. No multi-factor authentication is enforced for administrator accounts. Password policy allows 8-character passwords with minimal complexity. The VPN provides full internal network access upon authentication.',
        'impact': 'A compromised admin credential (via phishing, brute force, or credential stuffing) grants full access to the internal network, bypassing all perimeter controls.',
        'recommendation': '1. Enable MFA (TOTP or push notification) for all admin VPN accounts immediately.\n2. Extend MFA requirement to all VPN users within 30 days.\n3. Increase minimum password length to 14 characters.\n4. Implement account lockout after 5 failed attempts.\n5. Enable VPN session recording for admin accounts.',
    },
    {
        'id': 'F-005',
        'title': 'Default Credentials on Development MongoDB Instance',
        'severity': 'Critical',
        'cvss': '9.8',
        'asset': 'dev-db-03.db.acme.local',
        'asset_type': 'Database',
        'exposure': 'Internal',
        'cve': 'N/A',
        'description': 'The MongoDB instance on dev-db-03 is accessible on port 27017 without authentication. The default admin/admin credentials are active. The database contains a mirror of production data including customer records used for testing. The host is reachable from the internal network without network segmentation.',
        'impact': 'Any user on the internal network can access full production-equivalent data. If the internal network is compromised via VPN or other means, this becomes a trivial data exfiltration point.',
        'recommendation': '1. Enable MongoDB authentication immediately.\n2. Rotate all credentials.\n3. Bind MongoDB to localhost only (or specific internal subnet).\n4. Implement network segmentation between development and production networks.\n5. Scrub all PII from development databases; use synthetic data instead.',
    },
    {
        'id': 'F-006',
        'title': 'Public Read Access on S3 Bucket Containing PII Logs',
        'severity': 'High',
        'cvss': '7.2',
        'asset': 'acme-logs (S3)',
        'asset_type': 'Cloud Storage',
        'exposure': 'Internet-facing',
        'cve': 'N/A',
        'description': 'The S3 bucket "acme-logs" has a bucket policy granting read access to all principals (*). The bucket contains application logs that include customer email addresses, IP addresses, and session tokens. The bucket is listed in the public AWS S3 directory.',
        'impact': 'Anyone on the internet can download all logs containing PII. Session tokens in logs could enable session hijacking. GDPR breach notification may be required.',
        'recommendation': '1. Remove the public read policy immediately.\n2. Apply a restrictive bucket policy allowing only the log-writer IAM role.\n3. Enable S3 Block Public Access at the account level.\n4. Enable server-side encryption (SSE-KMS).\n5. Review all other S3 buckets for similar misconfigurations.\n6. Scrub session tokens from future log entries.',
    },
    {
        'id': 'F-007',
        'title': 'Vulnerable OpenSSL Version on Mail Server (Heartbleed)',
        'severity': 'Medium',
        'cvss': '5.0',
        'asset': 'mail01.mail.acme.local',
        'asset_type': 'Mail Server',
        'exposure': 'Internal',
        'cve': 'CVE-2014-0160',
        'description': 'The mail server is running a pinned Docker image with OpenSSL 1.0.1f, which is vulnerable to CVE-2014-0160 (Heartbleed). This allows an attacker to read up to 64KB of server memory per request, potentially exposing private keys and session tokens.',
        'impact': 'Exposure of TLS private keys would allow decryption of all mail traffic. Session tokens could enable account takeover.',
        'recommendation': '1. Rebuild the Docker image with OpenSSL 1.1.1 or later.\n2. Rotate the TLS certificate and private key.\n3. Rotate all mail user session tokens.\n4. Update the CI/CD pipeline to scan images for known vulnerabilities.\n5. Set up automated dependency scanning.',
    },
    {
        'id': 'F-008',
        'title': 'Stored Cross-Site Scripting on Marketing Blog',
        'severity': 'Medium',
        'cvss': '6.1',
        'asset': 'out.marketing.acme.local',
        'asset_type': 'Website',
        'exposure': 'Internet-facing',
        'cve': 'CVE-2023-44487',
        'description': 'The blog comment field on the marketing site does not sanitize user input before storing and rendering it. A stored XSS payload was confirmed by injecting a script tag that executes when any user views the comment. The site shares a CDN domain with the main application, creating a potential for cookie theft.',
        'impact': 'Attacker can steal session cookies of visitors, deface the site, or redirect users to phishing pages. Reputational damage if exploited publicly.',
        'recommendation': '1. Sanitize all user input using an HTML allowlist library.\n2. Set Content-Security-Policy headers (script-src self only).\n3. Set HttpOnly and Secure flags on all cookies.\n4. Implement output encoding for all dynamic content.\n5. Consider moving the blog to a separate domain to isolate cookies.',
    },
    {
        'id': 'F-009',
        'title': 'Excessive Admin Permissions on GitHub Organization',
        'severity': 'Medium',
        'cvss': '5.4',
        'asset': 'github.com/acme',
        'asset_type': 'Code Repository',
        'exposure': 'Internet-facing',
        'cve': 'N/A',
        'description': 'The GitHub organization "acme" has 12 members with admin role, including 4 contractors and 2 former employees whose accounts are still active. Admin role grants the ability to delete repositories, modify billing, and add/remove members. No audit log export is enabled.',
        'impact': 'A compromised or malicious admin account could delete all source code, inject backdoors, or exfiltrate proprietary code. No audit trail for forensic analysis.',
        'recommendation': '1. Review all admin members and reduce to least privilege.\n2. Remove access for former employees immediately.\n3. Enable GitHub Enterprise audit log export to SIEM.\n4. Require MFA for all organization members.\n5. Implement a quarterly access review process.',
    },
    {
        'id': 'F-010',
        'title': 'Unencrypted Backup Tapes in Transit',
        'severity': 'High',
        'cvss': '7.0',
        'asset': 'backup-tape-lot-0917',
        'asset_type': 'Backup',
        'exposure': 'Internal',
        'cve': 'N/A',
        'description': 'LTO-8 backup tapes containing full database backups are shipped to an offsite storage vendor in unencrypted form. The tapes contain customer PII, financial records, and proprietary source code. The shipping vendor does not provide chain-of-custody tracking.',
        'impact': 'Loss or theft of a single tape constitutes a full data breach. No ability to prove custody or detect interception.',
        'recommendation': '1. Encrypt all backup tapes using LTO hardware encryption with managed keys.\n2. Alternatively, migrate to cloud backup with KMS encryption.\n3. Require chain-of-custody documentation from the shipping vendor.\n4. Implement a tape inventory and tracking system.\n5. Update the data protection policy to mandate encryption at rest for all backups.',
    },
]


def build_report():
    doc = SimpleDocTemplate(OUTPUT, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=25*mm, bottomMargin=20*mm)

    story = []

    # === COVER PAGE ===
    story.append(Spacer(1, 80*mm))
    story.append(Paragraph("Penetration Testing Report", cover_title))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("ACME Corporation", cover_sub))
    story.append(Spacer(1, 2*mm))
    story.append(Paragraph("Prepared by: Sentrix Security Ltd.", cover_sub))
    story.append(Spacer(1, 20*mm))
    story.append(HRFlowable(width="60%", thickness=1, color=HexColor('#cccccc')))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph("Report Reference: SENT-2026-ACME-0914", cover_sub))
    story.append(Paragraph("Classification: CONFIDENTIAL", cover_sub))
    story.append(Paragraph("Date: 14 September 2026", cover_sub))
    story.append(Paragraph("Version: 1.0 (Final)", cover_sub))
    story.append(PageBreak())

    # === EXECUTIVE SUMMARY ===
    story.append(Paragraph("1. Executive Summary", h1))
    story.append(Paragraph(
        "Sentrix Security Ltd. was engaged by ACME Corporation to conduct an external and internal "
        "penetration test of their production infrastructure. The assessment was performed between "
        "5 September 2026 and 13 September 2026.", body))
    story.append(Paragraph(
        "A total of 10 vulnerabilities were identified across the assessed infrastructure. "
        "Of these, 4 are rated Critical, 3 are rated High, and 3 are rated Medium. "
        "The most severe findings involve remote code execution on the public-facing web server, "
        "SQL injection in the customer portal, default credentials on a development database, "
        "and missing multi-factor authentication on the administrative VPN.", body))
    story.append(Paragraph(
        "We recommend immediate remediation of all Critical findings within 72 hours. "
        "High severity findings should be addressed within 7 days. "
        "A full remediation plan with prioritized actions is included in this report.", body))

    story.append(Spacer(1, 6*mm))

    # === VULNERABILITY SUMMARY TABLE ===
    story.append(Paragraph("2. Vulnerability Summary", h1))
    header = ['ID', 'Title', 'Severity', 'CVSS', 'Affected Asset']
    data = [header]
    for f in FINDINGS:
        data.append([f['id'], Paragraph(f['title'][:60], body), f['severity'], f['cvss'], f['asset']])

    tbl = Table(data, colWidths=[18*mm, 75*mm, 22*mm, 15*mm, 40*mm])
    tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#ffffff'), HexColor('#f0f0f5')]),
    ]))
    # Color severity cells
    for i, f in enumerate(FINDINGS):
        tbl.setStyle(TableStyle([('TEXTCOLOR', (2, i+1), (2, i+1), SEV_COLORS[f['severity']]),
                                 ('FONTNAME', (2, i+1), (2, i+1), 'Helvetica-Bold')]))
    story.append(tbl)
    story.append(PageBreak())

    # === DETAILED FINDINGS ===
    story.append(Paragraph("3. Detailed Findings", h1))
    story.append(Paragraph(
        "Each finding below includes a description, impact assessment, and recommended remediation steps.", body))

    for f in FINDINGS:
        # Finding header
        sev_color = SEV_COLORS[f['severity']]
        story.append(Paragraph(f"{f['id']}: {f['title']}", finding_title))

        # Metadata table
        meta = [
            ['Severity:', f['severity'], 'CVSS:', f['cvss']],
            ['Affected Asset:', f['asset'], 'Asset Type:', f['asset_type']],
            ['Exposure:', f['exposure'], 'CVE:', f['cve']],
        ]
        meta_tbl = Table(meta, colWidths=[30*mm, 55*mm, 25*mm, 50*mm])
        meta_tbl.setStyle(TableStyle([
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (1, 0), (1, 0), sev_color),
            ('FONTNAME', (1, 0), (1, 0), 'Helvetica-Bold'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(meta_tbl)
        story.append(Spacer(1, 4*mm))

        story.append(Paragraph("<b>Description:</b>", body))
        story.append(Paragraph(f['description'], body))
        story.append(Spacer(1, 3*mm))

        story.append(Paragraph("<b>Impact:</b>", body))
        story.append(Paragraph(f['impact'], body))
        story.append(Spacer(1, 3*mm))

        story.append(Paragraph("<b>Recommendation:</b>", body))
        for line in f['recommendation'].split('\n'):
            story.append(Paragraph(line, body))
        story.append(Spacer(1, 3*mm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor('#dddddd')))
        story.append(Spacer(1, 4*mm))

    # === FOOTER ===
    story.append(Spacer(1, 10*mm))
    story.append(Paragraph("End of Report", cover_sub))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        "This report was prepared by Sentrix Security Ltd. for the exclusive use of ACME Corporation. "
        "Distribution is restricted to authorized personnel only. The findings and recommendations "
        "contained herein are based on the assessment conducted during the stated period and may not "
        "reflect changes made after the assessment date.", body))

    doc.build(story)
    print(f"Report generated: {OUTPUT}")


if __name__ == '__main__':
    build_report()

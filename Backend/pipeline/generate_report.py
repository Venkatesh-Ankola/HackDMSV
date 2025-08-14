
from fpdf import FPDF
import os
from datetime import datetime

# Dark yellow for MEDIUM
SEVERITY_COLORS = {
    "CRITICAL": (255, 0, 0),       # Red
    "HIGH": (255, 102, 0),         # Orange
    "MEDIUM": (204, 153, 0),       # Dark Yellow
    "LOW": (0, 153, 0),            # Green
}

class PDFReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.add_page()
        self.set_title("Vulnerability Report")
        self.add_title()
        self.row_fill_toggle = False

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def add_title(self):
        self.set_font("Arial", 'B', 16)
        self.cell(0, 10, "Vulnerability Report", ln=True, align='C')
        self.set_font("Arial", '', 12)
        self.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True, align='C')
        self.ln(10)

    def add_table_header(self):
        self.set_font("Arial", 'B', 12)
        self.set_fill_color(220, 220, 220)
        self.cell(40, 10, "CVE ID", 1, 0, 'C', True)
        self.cell(30, 10, "Severity", 1, 0, 'C', True)
        self.cell(20, 10, "CVSS", 1, 0, 'C', True)
        self.cell(40, 10, "Service", 1, 0, 'C', True)
        self.cell(0, 10, "Summary", 1, 1, 'C', True)

    def add_table_row(self, vuln, service):
        severity = vuln['severity'].upper()
        color = SEVERITY_COLORS.get(severity, (0, 0, 0))

        # Alternate row background
        self.row_fill_toggle = not self.row_fill_toggle
        if self.row_fill_toggle:
            self.set_fill_color(245, 245, 245)
            fill = True
        else:
            fill = False

        self.set_font("Arial", '', 11)
        self.set_text_color(0, 0, 0)

        self.cell(40, 10, vuln['cve_id'], 1, 0, '', fill)
        self.set_text_color(*color)
        self.cell(30, 10, severity.title(), 1, 0, '', fill)
        self.cell(20, 10, str(vuln['score']), 1, 0, '', fill)
        self.set_text_color(0, 0, 0)
        self.cell(40, 10, service[:18], 1, 0, '', fill)
        self.multi_cell(0, 10, vuln.get('short_summary', vuln['description']), 1, fill=fill)

    def add_detailed_section(self, data):
        self.add_page()
        self.set_font("Arial", 'B', 14)
        self.cell(0, 10, "Detailed Vulnerability Breakdown", ln=True)
        self.ln(5)

        for item in data:
            ip = item.get('ip', 'Unknown')
            service = item.get('product') or "Unknown"
            version = item.get('version') or "Unknown"
            cpe = item.get('cpe') or "Unknown"
            vulns = item.get('vulnerabilities', [])

            if not vulns:
                continue

            self.set_font("Arial", 'B', 12)
            self.cell(0, 10, f"IP: {ip} | Service: {service} | Version: {version}", ln=True)
            self.set_font("Arial", '', 11)
            self.cell(0, 10, f"CPE: {cpe}", ln=True)
            self.ln(3)

            for vuln in vulns:
                self.set_font("Arial", 'B', 11)
                self.cell(0, 10, f"CVE ID: {vuln['cve_id']}", ln=True)

                self.set_font("Arial", '', 11)
                self.cell(0, 10, f"Severity: {vuln['severity']} | CVSS: {vuln['score']}", ln=True)
                self.multi_cell(0, 10, f"Description: {vuln['description']}")
                if vuln.get("reference"):
                    self.set_text_color(0, 0, 255)
                    self.set_font('', 'U')  # underline
                    self.cell(0, 10, f"More Info: {vuln['reference']}", ln=True, link=vuln['reference'])
                    self.set_text_color(0, 0, 0)
                    self.set_font('', '')
                self.ln(5)

    def add_summary(self, summary_text):
        self.add_page()
        self.set_font("Arial", 'B', 14)
        self.cell(0, 10, "Executive Summary & Recommendations", ln=True)
        self.set_font("Arial", '', 11)
        self.multi_cell(0, 10, summary_text)

def generate_pdf_report(data, llm_summary, short_summaries, output_path="data/Vulnerability_Report.pdf"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf = PDFReport()

    all_vulns = []
    for item in data:
        service = item.get('product') or "Unknown"
        for vuln in item.get('vulnerabilities', []):
            vuln['short_summary'] = short_summaries.get(vuln['cve_id'], vuln['description'])
            all_vulns.append((vuln, service))

    if all_vulns:
        all_vulns.sort(key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x[0]['severity'].upper()))
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, "Vulnerability Overview", ln=True)
        pdf.ln(3)
        pdf.add_table_header()
        for vuln, service in all_vulns:
            pdf.add_table_row(vuln, service)

    pdf.add_detailed_section(data)
    pdf.add_summary(llm_summary)
    pdf.output(output_path)
    print(f"✅ Report generated at {output_path}")


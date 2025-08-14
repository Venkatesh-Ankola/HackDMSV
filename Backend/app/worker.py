
import os
from pipeline.nmap_generate import run_scan_and_parse
from pipeline.ask_llm import summarize_findings_and_vulns
from pipeline.generate_report import generate_pdf_report
from app.state_manager import set_status
from pathlib import Path

def generate_report_task(target, report_id):
    try:
        set_status(report_id, "processing")
        enriched_data = run_scan_and_parse(target)

        if not enriched_data:
            set_status(report_id, "failed")
            return

        # Single LLM call for executive summary + short summaries
        executive_summary, short_summaries = summarize_findings_and_vulns(enriched_data)

        report_path = f"data/{report_id}.pdf"
        generate_pdf_report(enriched_data, executive_summary, short_summaries, output_path=report_path)

        set_status(report_id, "done")

    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        set_status(report_id, "failed")


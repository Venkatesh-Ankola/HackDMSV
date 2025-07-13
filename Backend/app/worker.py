import os
from pipeline.nmap_generate import run_scan_and_parse
from pipeline.ask_llm import summarize_findings
from pipeline.generate_report import generate_pdf_report
from app.state_manager import set_status
from pathlib import Path

def generate_report_task(target, report_id):
    try:
        set_status(report_id, "processing")
        enriched_data = run_scan_and_parse(target)
        # print(f"Enriched data for {target}: {enriched_data}")
        if not enriched_data:
            set_status(report_id, "failed")
            return

        llm_summary = summarize_findings(enriched_data)
        report_path = f"data/{report_id}.pdf"
        generate_pdf_report(enriched_data, llm_summary, output_path=report_path)
        set_status(report_id, "done")
    except Exception as e:
        print(f"Report generation failed: {e}")
        set_status(report_id, "failed")


# IntelliPatch — LLM-Powered Automated Patch-Management Workflow  
> “Upload an Nmap scan → get an action-ready, exec-friendly PDF report in under 2 minutes.”

---

## Table of Contents

1. [Problem Statement](#problem-statement)  
2. [Solution Overview](#solution-overview)  
3. [System Architecture](#system-architecture)  
4. [Project Structure](#project-structure)  
5. [Setup & Usage](#setup--usage)  
6. [Detailed Workflow](#detailed-workflow)  
7. [Extending the Project](#extending-the-project)  
8. [Hackathon Deliverables](#hackathon-deliverables)  
9. [License](#license)

---

## Problem Statement

In the current cybersecurity landscape, manual patch management is slow, error-prone, and often disconnected from executive priorities.  
With over 40,000 new CVEs disclosed in 2024, traditional tools leave security teams overwhelmed and response times delayed.

**IntelliPatch** addresses this challenge by automating the entire vulnerability lifecycle—**Detection → Enrichment → Reasoning → Reporting**—with LLMs and open-source tooling.

---

## Solution Overview

- **Scan**: Security teams upload an Nmap service/version scan (XML).  
- **Parse**: Extracts IPs, ports, product names, versions, and possible CPEs.  
- **Enrich**: Matches against known vulnerabilities using NVD and CISA KEV APIs.  
- **Reason**: Uses GPT-4o to explain severity, impact, and suggest actionable fixes.  
- **Generate**: Outputs both Markdown and styled PDF reports.  
- **Query**: Users can ask follow-up questions in natural language—responses are generated contextually.

---

## System Architecture

![Architecture Diagram](https://github.com/Venkatesh-Ankola/HackDMSV/blob/70a2d75a6a7a8551251f4b4db92ef61263ff595d/assets/architecture.png)


---

## Project Structure

```bash
HackDMSV/
├── app/
│   ├── main.py                # FastAPI backend entry point
│   ├── state_manager.py       # Manages report status
│   └── worker.py              # Background task for report generation
│
├── pipeline/
│   ├── ask_llm.py             # Interact with OpenAI API
│   ├── generate_report.py     # Generate Markdown and PDF reports
│   ├── main.py                # End-to-end CLI runner
│   ├── nmap_generate.py       # Run and parse Nmap scan
│   └── query_pdf.py           # Handle LLM-based PDF queries
│
├── data/
│   └── embeddings/            # (Optional) LLM vector storage
├── frontend/
│   └── index.html             # Frontend interface
├── .env                       # Keys for OpenAI, NVD, HuggingFace
├── requirements.txt
└── README.md                  # This file
```

---

## Setup & Usage

You can use IntelliPatch in two ways:  
**(1) Via hosted UI** or **(2) Local development environment.**

---

### Option 1: Hosted Version (No Setup Needed)

Access IntelliPatch directly via:

**URL:** http://hack-dmsv.s3-website.ap-south-1.amazonaws.com/

#### Steps:
- Visit the above link in any modern browser  
- Enter a target IP/domain  
- Wait for the PDF generation to complete  
- Download the generated report  
- Use the query box to ask questions like _“List critical unpatched vulnerabilities”_

---

### Option 2: Local Deployment (Developer Mode)

#### Step 1: Clone the Repository

```bash
git clone https://github.com/Venkatesh-Ankola/HackDMSV.git
cd HackDMSV
```

#### Step 2: Backend Setup

```bash
cd backend
pip install -r requirements.txt
```

Create a `.env` file in the backend directory:

```env
OPENAI_API_KEY=your_openai_key
NVD_API_KEY=your_nvd_api_key
HF_TOKEN=your_huggingface_token
```

Run the backend:

```bash
uvicorn app.main:app --reload
```

> Backend will be available at: `http://127.0.0.1:8000`

---

#### Step 3: Frontend Usage

```bash
cd ../frontend
```

No installation needed. Just open `index.html` in your browser.  
The frontend is pre-wired to interact with `http://127.0.0.1:8000`.

---

## Detailed Workflow

1. User enters a domain/IP  
2. Backend launches Nmap service scan (or uses pre-scanned XML)  
3. Results are parsed and CVEs are fetched from NVD + KEV  
4. GPT-4o analyzes vulnerabilities and prepares a contextual explanation  
5. A styled PDF report is generated and made available for download  
6. Users can ask natural-language queries to interact with the results

---

## Extending the Project

- Add webhooks for real-time alerts  
- Use LangChain or LlamaIndex for advanced querying  
- Build dashboards for multi-target patch posture  
- Integrate Slack/Jira for remediation workflows  
- Switch to offline LLMs for on-prem use cases

---

## Hackathon Deliverables

- ✅ Working backend with FastAPI and async pipeline  
- ✅ PDF report generation with GPT-4o  
- ✅ Hosted demo link with no install required  
- ✅ Natural-language query interface  
- ✅ Modular code for easy extension



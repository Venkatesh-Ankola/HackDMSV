from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi import Query
from uuid import uuid4
from app.worker import generate_report_task
from app.state_manager import get_status
from fastapi.middleware.cors import CORSMiddleware
from pipeline.query_pdf import query_pdf_with_llm
import os

import os
import torch
# import chromadb
# from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from huggingface_hub import login, hf_hub_url
from dotenv import load_dotenv

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from huggingface_hub import login, hf_hub_download
# from chromadb import PersistentClient

# chroma_collection = None

@app.on_event("startup")
def startup_event():
   
    load_dotenv()
    HF_TOKEN = os.getenv("HF_TOKEN")
    login(token=HF_TOKEN)

    
    repo_id = "sushanrai/CVE_BERT_DMSV"
    filename = "cve_embeddings.pt"

    
    local_path = hf_hub_download(repo_id=repo_id, filename=filename, local_dir="./embeddings")
    
    
    data = torch.load(local_path, map_location="cpu")
    cve_texts = data["cve_texts"]

    

@app.post("/trigger_report")
async def trigger_report(target: str, background_tasks: BackgroundTasks):
    report_id = str(uuid4())
    background_tasks.add_task(generate_report_task, target, report_id)
    return {"report_id": report_id}

@app.get("/status_report/{report_id}")
async def status_report(report_id: str):
    status = get_status(report_id)

    if status == "not_found":
        raise HTTPException(status_code=404, detail="Report not found")

    elif status == "processing":
        return {"status": "processing"}

    elif status == "failed":
        return {"status": "failed", "message": "Report generation failed"}

    elif status == "done":
        file_path = f"data/{report_id}.pdf"
        if os.path.exists(file_path):
            return {"status": "done"}
        else:
            return {"status": "done", "error": "PDF not found"}

    return {"status": "unknown"}

@app.get("/get_report/{report_id}")
def get_report(report_id: str):
    file_path = f"data/{report_id}.pdf"
    if os.path.exists(file_path):
        return FileResponse(path=file_path, filename="patch_report.pdf", media_type="application/pdf")
    else:
        raise HTTPException(status_code=404, detail="PDF report not found")
    
@app.get("/query_report/{report_id}")
def query_report(report_id: str, question: str = Query(...)):
    pdf_path = f"data/{report_id}.pdf"
    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=404, detail="PDF report not found")

    answer = query_pdf_with_llm(pdf_path, question)
    return {"question": question, "answer": answer}


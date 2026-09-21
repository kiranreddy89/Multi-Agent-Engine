import os
import shutil
import urllib.request
import json
from typing import Optional
from pydantic import BaseModel

from fastapi import FastAPI, UploadFile, File, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.config import OLLAMA_API_URL, OLLAMA_LLM_MODEL
from backend.database.chroma_manager import ChromaManager
from backend.utils.chunker import process_file_into_chunks
from backend.agents.planning_agent import PlanningAgent
from backend.agents.research_agent import ResearchAgent
from backend.agents.validation_agent import ValidationAgent
from backend.agents.execution_agent import ExecutionAgent
from backend.agents.orchestrator import MultiAgentOrchestrator
from backend.utils.test_bench import SecurityTestBench

app = FastAPI(
    title="SentinelAI - Local Agentic Cybersecurity Workspace",
    description="Multi-agent security intelligence workspace powered by Planning, Research, Validation, and Execution agents running on local GPT-OSS.",
    version="2.0.0"
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instantiate Database and Multi-Agent Orchestrator
chroma_manager = ChromaManager()
planning_agent = PlanningAgent(model_name=OLLAMA_LLM_MODEL, api_url=OLLAMA_API_URL)
research_agent = ResearchAgent(chroma_manager=chroma_manager)
validation_agent = ValidationAgent(model_name=OLLAMA_LLM_MODEL, api_url=OLLAMA_API_URL)
execution_agent = ExecutionAgent(model_name=OLLAMA_LLM_MODEL, api_url=OLLAMA_API_URL)

orchestrator = MultiAgentOrchestrator(
    model_name=OLLAMA_LLM_MODEL,
    api_url=OLLAMA_API_URL,
    chroma_manager=chroma_manager,
    planning_agent=planning_agent,
    research_agent=research_agent,
    validation_agent=validation_agent,
    execution_agent=execution_agent
)
coordinator = orchestrator  # Alias for backward compatibility
test_bench = SecurityTestBench(coordinator=orchestrator)

# Define request schemas
class QueryRequest(BaseModel):
    query: str

class DirectoryIngestRequest(BaseModel):
    directory_path: str

@app.get("/api/status")
async def get_status():
    """
    Check connectivity to Ollama LLM and ChromaDB vector store.
    """
    # 1. Check Ollama Status
    ollama_status = "offline"
    available_models = []
    try:
        url = f"{OLLAMA_API_URL.rstrip('/')}/api/tags"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            ollama_status = "online"
            available_models = [m["name"] for m in res_data.get("models", [])]
    except Exception as e:
        ollama_status = f"offline (error: {e})"

    # 2. Check Database Status
    db_stats = chroma_manager.get_collection_stats()
    
    # 3. Overall System Health
    system_health = "healthy"
    if ollama_status != "online" or db_stats["status"] != "healthy":
        system_health = "degraded"
        
    # Check if configured model is available in Ollama
    model_loaded = False
    for m in available_models:
        if OLLAMA_LLM_MODEL in m or m in OLLAMA_LLM_MODEL or ("gpt-oss" in OLLAMA_LLM_MODEL and "gpt-oss" in m):
            model_loaded = True
            break

    return {
        "status": system_health,
        "ollama": {
            "status": "online" if ollama_status == "online" else "offline",
            "url": OLLAMA_API_URL,
            "configured_llm": OLLAMA_LLM_MODEL,
            "models_installed": available_models,
            "gpt_oss_loaded": model_loaded,
            "llm_loaded": model_loaded,
            "gemma_loaded": model_loaded  # Backward compatibility for legacy UI
        },
        "agents": [
            {"name": "Planning Agent", "role": "Intent Classification & Investigation Roadmap", "status": "active"},
            {"name": "Research Agent", "role": "RAG Vector Retrieval & IOC Extraction", "status": "active"},
            {"name": "Validation Agent", "role": "False Positive Verification & MITRE Mapping", "status": "active"},
            {"name": "Execution Agent", "role": "Containment Playbooks & Report Compilation", "status": "active"}
        ],
        "vector_db": db_stats
    }

@app.post("/api/analyze")
async def analyze_input(request: QueryRequest):
    """
    Submit a log snippet, CVE, or security prompt. 
    Runs the multi-agent reasoning flow.
    """
    if not request.query.strip():
         raise HTTPException(status_code=400, detail="Query cannot be empty.")
    try:
        result = coordinator.process_request(request.query)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Orchestration failure: {e}")

@app.post("/api/ingest")
async def ingest_file(
    file: UploadFile = File(...), 
    chunk_size: int = Form(500), 
    overlap: int = Form(100)
):
    """
    Upload a security document (PDF, TXT, MD, DOCX, JSON) and index it into ChromaDB.
    """
    # Create temp directory
    temp_dir = "./data/temp_uploads"
    os.makedirs(temp_dir, exist_ok=True)
    
    temp_file_path = os.path.join(temp_dir, file.filename)
    try:
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        # Parse and Chunk
        chunks = process_file_into_chunks(temp_file_path, chunk_size=chunk_size, overlap=overlap)
        
        if not chunks:
            raise HTTPException(status_code=400, detail=f"No valid text could be extracted from {file.filename}.")
            
        # Add to ChromaDB
        success = chroma_manager.add_documents(chunks)
        if not success:
             raise HTTPException(status_code=500, detail="Failed to write chunks to vector database.")
             
        return {
            "status": "success",
            "filename": file.filename,
            "chunks_created": len(chunks),
            "message": f"Successfully ingested {file.filename} into knowledge base."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up temp file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@app.post("/api/ingest-directory")
async def ingest_directory(request: DirectoryIngestRequest):
    """
    Scan a directory on the local machine and index all supported files.
    """
    dir_path = request.directory_path
    if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
        raise HTTPException(status_code=400, detail="Provided path is not a valid directory.")
        
    supported_extensions = [".txt", ".md", ".markdown", ".pdf", ".docx", ".json"]
    files_processed = []
    total_chunks = 0
    errors = []
    
    for root, _, files in os.walk(dir_path):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in supported_extensions:
                full_path = os.path.join(root, f)
                try:
                    chunks = process_file_into_chunks(full_path)
                    if chunks:
                        chroma_manager.add_documents(chunks)
                        files_processed.append(f)
                        total_chunks += len(chunks)
                except Exception as e:
                    errors.append(f"Error reading {f}: {str(e)}")
                    
    return {
        "status": "success",
        "directory": dir_path,
        "files_indexed": files_processed,
        "total_chunks_created": total_chunks,
        "errors": errors
    }

@app.post("/api/db-reset")
async def reset_database():
    """
    Wipe and rebuild the vector database collection.
    """
    success = chroma_manager.clear_collection()
    if not success:
        raise HTTPException(status_code=500, detail="Failed to reset database.")
    return {"status": "success", "message": "Vector database cleared successfully."}

@app.post("/api/test-bench")
async def run_scenarios():
    """
    Execute all 8 benchmark test scenarios and report results.
    """
    try:
        report = test_bench.run_all()
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Benchmark execution failed: {e}")

# Frontend static serving routes
# Ensure frontend folders exist before mounting
os.makedirs("frontend/css", exist_ok=True)
os.makedirs("frontend/js", exist_ok=True)

# Mount CSS/JS paths
app.mount("/css", StaticFiles(directory="frontend/css"), name="css")
app.mount("/js", StaticFiles(directory="frontend/js"), name="js")

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """
    Serve the dashboard HTML index page.
    """
    index_path = "frontend/index.html"
    if not os.path.exists(index_path):
        # Fail-safe message if HTML doesn't exist yet
        return HTMLResponse("<h1>SentinelAI UI Dashboard is under construction. Please check back in a few seconds.</h1>")
    return FileResponse(index_path)

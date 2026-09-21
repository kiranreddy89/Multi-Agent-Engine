# SentinelAI: Local Multi-Agent Cybersecurity Workspace - Setup Instructions

This document provides step-by-step instructions on setting up the SentinelAI workspace on your local machine.

---

## System Architecture

SentinelAI is a self-hosted agentic platform. It runs fully local and consists of:
1. **Frontend**: A sleek glassmorphic dashboard (`frontend/index.html`, `frontend/css/styles.css`, `frontend/js/app.js`) served by FastAPI.
2. **Backend**: FastAPI app (`backend/main.py`) which orchestrates the 4 specialized agents (Planning, Research, Validation, Execution).
3. **Database**: Persistent local ChromaDB database storing embedded document chunks.
4. **LLM Server**: Ollama running locally, running `gpt-oss` (reasoning/logic) and `nomic-embed-text` (vector embeddings).

---

## Step 1: Install Python & System Dependencies

Make sure you have Python 3.10 or higher installed.

1. **Verify Python Installation**:
   ```bash
   python --version
   ```
2. **Install virtualenv (Recommended)**:
   It is highly recommended to run the backend in a virtual environment to prevent package conflicts:
   ```bash
   python -m venv venv
   # On Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # On Windows (CMD):
   .\venv\Scripts\activate.bat
   # On macOS/Linux:
   source venv/bin/activate
   ```

---

## Step 2: Install Python Libraries

Install the backend dependencies:
```bash
pip install -r backend/requirements.txt
```
*(The dependencies include: `fastapi`, `uvicorn`, `chromadb`, `ollama`, `pydantic`, `python-multipart`, `pypdf`, `python-docx`, `jinja2`)*

---

## Step 3: Set Up and Start Ollama

Since GPT-OSS runs locally, you must run it through Ollama.

1. **Download Ollama**: Download and install Ollama for your OS from [Ollama's Official Website](https://ollama.com).
2. **Run Ollama**: Ensure Ollama is running in your background or menu bar.
3. **Pull GPT-OSS Model**:
   Open a terminal/command prompt and run:
   ```bash
   ollama pull gpt-oss
   ```
4. **Pull Embedding Model**:
   For the Research Agent's vector retrieval (RAG) system, download the `nomic-embed-text` model:
   ```bash
   ollama pull nomic-embed-text
   ```
5. **Verify Running Models**:
   Verify both models are successfully downloaded:
   ```bash
   ollama list
   ```

---

## Step 4: Download External Datasets (Optional but Recommended)

Refer to [requirements_external.md](file:///c:/sentinalai/requirements_external.md) for direct download links and directory placement for threat intelligence documents, MITRE ATT&CK catalogs, and CVE lists to populate your local Knowledge Base.

---

## Step 5: Start SentinelAI

Run the following command in the project root directory (`c:\sentinalai`):

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

After starting, open your browser and navigate to:
**[http://127.0.0.1:8000](http://127.0.0.1:8000)**

You will be greeted by the SentinelAI Dashboard, which displays:
- Active model connections (GPT-OSS) and ChromaDB status.
- Document loading and embedding interface.
- 4-Agent pipeline protocol flow (Planning ➔ Research ➔ Validation ➔ Execution).
- Detailed multi-agent analysis report generator.
- Benchmark testing suite to test system metrics.

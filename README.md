# Multi-Agent Engine 🛡️

**Multi-Agent Engine** is a self-hosted, multi-agent cybersecurity workspace designed to assist with security analysis, threat intelligence, and knowledge retrieval using locally running AI models.

The platform combines multiple specialized AI agents with **Retrieval-Augmented Generation (RAG)**, **ChromaDB**, and **Ollama** to provide a local cybersecurity analysis environment.

## ✨ Features

* 🤖 **Multi-Agent Architecture**

  * **Planning Agent**: Problem deconstruction, intent detection, and strategic investigation roadmapping
  * **Research Agent**: RAG vector knowledge search, threat intelligence gathering, and IOC extraction
  * **Validation Agent**: Threat verification, false-positive elimination, MITRE ATT&CK alignment, and severity scoring
  * **Execution Agent**: Containment command generation, mitigation playbooks, and executive report compilation

* 🧠 **Local AI Processing**

  * Runs locally using Ollama
  * Uses `gpt-oss` for multi-agent reasoning and analysis
  * Uses `nomic-embed-text` for vector embeddings

* 🔎 **RAG-Based Knowledge System**

  * Retrieves relevant cybersecurity information from locally indexed documents
  * Uses ChromaDB as the vector database

* 🛡️ **Cybersecurity Knowledge Base**

  * CVE / vulnerability information
  * MITRE ATT&CK techniques
  * OWASP security guidance
  * Malware and threat intelligence reports
  * Sigma, YARA, Snort and Suricata detection rules

* 📊 **Security Analysis Dashboard**

  * Model and database status
  * Document ingestion
  * Multi-agent communication/protocol flow
  * Actionable containment playbooks & reports
  * Benchmark testing

* 🔒 **Self-Hosted**

  * Designed to run locally
  * No requirement to send cybersecurity data to a remote AI service

## 🏗️ System Architecture

```text
                         SentinelAI
                             │
                             ▼
                    ┌─────────────────┐
                    │    Frontend     │
                    │ HTML / CSS / JS │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    FastAPI      │
                    │    Backend      │
                    └────────┬────────┘
                             │
                             ▼
                ┌─────────────────────────┐
                │ Multi-Agent Orchestrator│
                └────────────┬────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼                   ▼
    ┌──────────┐        ┌──────────┐        ┌──────────┐        ┌──────────┐
    │ Planning │   ➔    │ Research │   ➔    │Validation│   ➔    │Execution │
    │  Agent   │        │  Agent   │        │  Agent   │        │  Agent   │
    └──────────┘        └────┬─────┘        └──────────┘        └──────────┘
                             │
                             ▼
                        ┌──────────┐
                        │ ChromaDB │
                        │   RAG    │
                        └────┬─────┘
                             │
                             ▼
                     Local Knowledge
                        Documents

                             Ollama
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
                 gpt-oss           nomic-embed-text
```

## 📁 Project Structure

```text
sentinalai/
│
├── backend/
│   ├── agents/
│   │   ├── planning_agent.py
│   │   ├── research_agent.py
│   │   ├── validation_agent.py
│   │   ├── execution_agent.py
│   │   ├── orchestrator.py
│   │   └── coordinator.py
│   │
│   ├── database/
│   │   └── chroma_manager.py
│   │
│   ├── utils/
│   │   ├── chunker.py
│   │   └── test_bench.py
│   │
│   ├── config.py
│   ├── main.py
│   └── requirements.txt
│
├── frontend/
│   ├── css/
│   │   └── styles.css
│   ├── js/
│   │   └── app.js
│   └── index.html
│
├── data/
│   └── chromadb/
│
├── requirements_external.md
├── setup_instructions.md
├── README.md
└── .gitignore
```

## ⚙️ Requirements

Before running SentinelAI, make sure you have:

* Python 3.10+
* Ollama
* `gpt-oss`
* `nomic-embed-text`

Install the Python dependencies with:

```bash
pip install -r backend/requirements.txt
```

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd sentinalai
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

On Windows PowerShell:

```bash
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Install and configure Ollama

Pull the required models:

```bash
ollama pull gpt-oss
ollama pull nomic-embed-text
```

Verify them with:

```bash
ollama list
```

### 5. Start SentinelAI

From the project root:

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Then open:

```text
http://127.0.0.1:8000
```

## 📚 Knowledge Base

SentinelAI can be enriched with external cybersecurity datasets and security documentation.

Recommended sources include:

* CISA Known Exploited Vulnerabilities
* NVD / CVE information
* MITRE ATT&CK
* OWASP security guidance
* Malware and threat intelligence reports
* Sigma rules
* YARA rules
* Snort and Suricata rules

Detailed dataset sources and ingestion instructions are available in:

**`requirements_external.md`**

## 📖 Documentation

For complete installation and configuration instructions, see:

**`setup_instructions.md`**

For recommended cybersecurity datasets and knowledge-base ingestion sources, see:

**`requirements_external.md`**

## 🔬 Technologies Used

| Component       | Technology            |
| --------------- | --------------------- |
| Backend         | Python, FastAPI       |
| Frontend        | HTML, CSS, JavaScript |
| AI Runtime      | Ollama                |
| Reasoning Model | GPT-OSS               |
| Embedding Model | Nomic Embed Text      |
| Vector Database | ChromaDB              |
| Architecture    | 4-Agent Pipeline + RAG|

## 🎯 Project Goal

The goal of SentinelAI is to provide a **local, intelligent cybersecurity workspace** capable of combining specialized AI agents with security knowledge retrieval to assist in understanding and analyzing cybersecurity-related information.

## ⚠️ Disclaimer

SentinelAI is intended for **educational, research, and authorized cybersecurity purposes**.

Only use the system, datasets, and security analysis capabilities on systems and information that you are authorized to access or analyze.

## 👥 Contributors

* **C.Charith Reddy** — Project Developer
* **Y.Kiran Kumar Reddy** — Project Developer


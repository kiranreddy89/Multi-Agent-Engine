import re
from typing import List, Dict, Any

from backend.database.chroma_manager import ChromaManager
from backend.config import TOP_K_RETRIEVAL

class ResearchAgent:
    """
    Research Agent (Threat Intelligence & RAG Grounding).
    Responsible for:
    1. Extracting IOCs (IP addresses, CVE identifiers, URLs, hashes, attack strings) from inputs.
    2. Querying the local ChromaDB vector store using search queries provided by the Planning Agent.
    3. Filtering, ranking, and assembling authoritative cybersecurity documentation and technical evidence.
    4. Returning structured intelligence to the Validation Agent.
    """
    def __init__(self, chroma_manager: ChromaManager = None):
        self.chroma_manager = chroma_manager or ChromaManager()

    def research(self, user_input: str, queries: List[str] = None) -> Dict[str, Any]:
        """
        Executes technical intelligence gathering and RAG vector searches.
        """
        search_queries = queries or [user_input]
        # Always ensure the original input or core keywords are also included
        if user_input not in search_queries:
            search_queries.append(user_input[:250])

        all_chunks = []
        seen_chunk_ids = set()

        # 1. Query ChromaDB for all supplied research topics
        try:
            for q in search_queries:
                if not q or len(q.strip()) < 3:
                    continue
                results = self.chroma_manager.query_documents(q, top_k=TOP_K_RETRIEVAL)
                for res in results:
                    chunk_id = res.get("id") or f"{res['metadata'].get('source')}_{res['metadata'].get('chunk_index')}"
                    if chunk_id not in seen_chunk_ids:
                        seen_chunk_ids.add(chunk_id)
                        all_chunks.append(res)
        except Exception as e:
            print(f"[ResearchAgent] RAG query error: {e}")

        # 2. Extract IOCs from user input
        extracted_iocs = self._extract_iocs(user_input)

        # 3. Compile Combined Context
        if all_chunks:
            combined_context = "\n=== RETRIEVED THREAT INTEL CONTEXT START ===\n"
            for idx, ch in enumerate(all_chunks[:6]):
                source = ch["metadata"].get("source", "Knowledge Base")
                score = ch.get("score", 0.0)
                combined_context += (
                    f"[{idx+1}] Source: {source} (Relevance Score: {score:.4f})\n"
                    f"Content: {ch['text']}\n\n"
                )
            combined_context += "=== RETRIEVED THREAT INTEL CONTEXT END ==="
        else:
            combined_context = "No direct vector match found in local ChromaDB knowledge base."

        return {
            "status": "success",
            "confidence": 1.0,
            "result": {
                "chunks": all_chunks[:6],
                "extracted_iocs": extracted_iocs,
                "searched_queries": search_queries,
                "combined_context": combined_context
            }
        }

    def _extract_iocs(self, text: str) -> List[Dict[str, str]]:
        """
        Heuristic regex extractor for security IOCs.
        """
        iocs = []

        # IPv4 pattern
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        for ip in set(ips):
            # Exclude standard subnet masks or loopbacks if desired
            iocs.append({"type": "IPv4 Address", "value": ip})

        # CVE pattern
        cves = re.findall(r'\bCVE-\d{4}-\d{4,7}\b', text, re.IGNORECASE)
        for cve in set(cves):
            iocs.append({"type": "CVE Identifier", "value": cve.upper()})

        # SHA256 / MD5 hashes
        sha256s = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
        for h in set(sha256s):
            iocs.append({"type": "SHA-256 Hash", "value": h})

        md5s = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
        for m in set(md5s):
            iocs.append({"type": "MD5 Hash", "value": m})

        # Suspicious attack signatures / keywords
        attack_signatures = [
            ("SQL Injection", ["union select", "or 1=1", "admin_users--", "concat(username"]),
            ("Cross-Site Scripting", ["<script>", "alert(", "document.cookie", "fetch("]),
            ("Ransomware", [".wannacry", "crypto activity", "tor exit node", "readme file"]),
            ("Brute Force", ["failed for root", "failed for admin", "authentication failed"]),
            ("Denial of Service", ["/api/login", "flood", "high volume"]),
            ("Malware / Trojan", ["cozybear", "loader", "svchost.exe", "updater_installer.exe"])
        ]

        text_lower = text.lower()
        for threat_type, patterns in attack_signatures:
            for pattern in patterns:
                if pattern in text_lower:
                    iocs.append({"type": "Attack Pattern Signature", "value": f"{threat_type} indicator ({pattern})"})
                    break

        return iocs

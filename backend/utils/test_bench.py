import time
from typing import Dict, Any, List
from backend.agents.coordinator import CoordinatorAgent

# Predefined security scenarios for Phase 9 testing
BENCHMARK_SCENARIOS = [
    {
        "id": "scenario_1",
        "name": "Normal Web Traffic",
        "description": "Standard legitimate HTTP GET request in web server logs.",
        "input": '192.168.1.100 - - [27/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 2326 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
        "expected_classification": "Normal"
    },
    {
        "id": "scenario_2",
        "name": "SQL Injection Attack",
        "description": "Exploit attempt targeting SQL backend via URL parameters.",
        "input": '192.168.1.105 - - [27/Jul/2026:10:05:00 +0000] "GET /products.php?id=1%20UNION%20SELECT%20NULL,username,password%20FROM%20admin_users-- HTTP/1.1" 200 482',
        "expected_classification": "SQL Injection"
    },
    {
        "id": "scenario_3",
        "name": "Cross-Site Scripting (XSS)",
        "description": "Injecting malicious script tags into input fields.",
        "input": '192.168.1.106 - - [27/Jul/2026:10:07:00 +0000] "POST /submit_comment.php HTTP/1.1" 200 128 "user_name=alice&comment=<script>alert(document.cookie);</script>"',
        "expected_classification": "Cross-Site Scripting"
    },
    {
        "id": "scenario_4",
        "name": "Ransomware Indicators",
        "description": "Execution of suspicious svchost and encryption of user files.",
        "input": 'Alert: Process "svchost.exe" spawned from "C:\\Users\\Public\\". File system activity: 45 files written in 1 second with extension ".wannacry". Outbound connection established to 185.220.101.5 (Tor Exit Node).',
        "expected_classification": "Ransomware"
    },
    {
        "id": "scenario_5",
        "name": "Brute Force Attack",
        "description": "Multiple failed SSH authentication attempts followed by a login success from the same IP.",
        "input": (
            "2026-07-27 10:10:01 SSH authentication failed for root from 203.0.113.50 port 54322 ssh2\n"
            "2026-07-27 10:10:03 SSH authentication failed for root from 203.0.113.50 port 54326 ssh2\n"
            "2026-07-27 10:10:05 SSH authentication failed for admin from 203.0.113.50 port 54330 ssh2\n"
            "2026-07-27 10:10:08 SSH authentication success for admin from 203.0.113.50 port 54334 ssh2"
        ),
        "expected_classification": "Brute Force"
    },
    {
        "id": "scenario_6",
        "name": "DDoS HTTP Flood",
        "description": "High volume HTTP requests to a single endpoint in a short window.",
        "input": "\n".join([f'198.51.100.72 - - [27/Jul/2026:10:15:00 +0000] "GET /api/login HTTP/1.1" 200 45' for _ in range(30)]),
        "expected_classification": "DDoS"
    },
    {
        "id": "scenario_7",
        "name": "Malware Hashes (Known File Signature)",
        "description": "Download of file with SHA-256 fingerprint matches active malware campaigns.",
        "input": 'Endpoint Protection: File download blocked. File path: C:\\Downloads\\update_installer.exe. SHA-256: 275a021bcfb6489e5444e706024472251bb4c17220042456e30026e85561fb77 (CozyBear Loader).',
        "expected_classification": "Malware"
    },
    {
        "id": "scenario_8",
        "name": "Zero-day vulnerability discussion",
        "description": "Threat report on a new unpatched vulnerability in an Apache server configuration.",
        "input": 'Security Blog post: "Exploiting CVE-2026-99999 - a zero-day remote code execution vulnerability in Apache HTTP Server 2.4.99. Attackers exploit a header parse overflow to run native machine code as root."',
        "expected_classification": "Zero-day"
    }
]

class SecurityTestBench:
    """
    Test Bench Suite.
    Runs cybersecurity benchmarks against the Multi-Agent system.
    Calculates execution metrics: Latency, Accuracy, Retrieval Relevance, and Hallucination Check.
    """
    def __init__(self, coordinator: CoordinatorAgent = None):
        self.coordinator = coordinator or CoordinatorAgent()

    def run_scenario(self, scenario: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs a single test scenario and computes metrics.
        """
        start_time = time.time()
        
        # Run through the Coordinator Agent
        response = self.coordinator.process_request(scenario["input"])
        
        end_time = time.time()
        latency = end_time - start_time
        
        # Calculate Metrics
        analysis = response.get("analysis_raw", {})
        classification = analysis.get("classification", "")
        
        # 1. Classification Accuracy Check
        expected = scenario["expected_classification"].lower()
        actual = classification.lower()
        is_accurate = (expected in actual) or (actual in expected)
        
        # 2. Retrieval Relevance
        retrieved_chunks = response.get("retrieved_chunks", [])
        has_retrieval = len(retrieved_chunks) > 0
        
        # 3. Hallucination Check (Basic heuristic check: did LLM return confidence > 0 and valid keys?)
        is_hallucinated = False
        if not response.get("report") or (response.get("intent") == "error"):
            is_hallucinated = True
            
        # 4. Latency
        return {
            "scenario_id": scenario["id"],
            "name": scenario["name"],
            "input": scenario["input"],
            "expected_classification": scenario["expected_classification"],
            "actual_classification": classification or "None / Error",
            "severity": analysis.get("severity", "Info"),
            "confidence": analysis.get("confidence_score", 0.0),
            "latency_seconds": round(latency, 2),
            "is_accurate": is_accurate,
            "has_retrieval": has_retrieval,
            "is_hallucinated": is_hallucinated,
            "report_summary": response.get("report")[:300] + "...",
            "communication_logs_count": len(response.get("communication_logs", []))
        }

    def run_all(self) -> Dict[str, Any]:
        """
        Runs all 8 scenarios and returns compiled statistics.
        """
        results = []
        total_latency = 0.0
        correct_count = 0
        retrieval_hits = 0
        hallucination_hits = 0
        
        for sc in BENCHMARK_SCENARIOS:
            print(f"Running benchmark: {sc['name']}...")
            res = self.run_scenario(sc)
            results.append(res)
            
            total_latency += res["latency_seconds"]
            if res["is_accurate"]:
                correct_count += 1
            if res["has_retrieval"]:
                retrieval_hits += 1
            if res["is_hallucinated"]:
                hallucination_hits += 1
                
        total_cases = len(BENCHMARK_SCENARIOS)
        
        return {
            "timestamp": time.time(),
            "total_cases": total_cases,
            "accuracy_rate": round(correct_count / total_cases * 100, 2) if total_cases > 0 else 0.0,
            "average_latency_seconds": round(total_latency / total_cases, 2) if total_cases > 0 else 0.0,
            "retrieval_rate": round(retrieval_hits / total_cases * 100, 2) if total_cases > 0 else 0.0,
            "hallucination_rate": round(hallucination_hits / total_cases * 100, 2) if total_cases > 0 else 0.0,
            "results": results
        }

if __name__ == "__main__":
    # If run directly, execute the test bench
    bench = SecurityTestBench()
    print("==================================================")
    print("         SENTINELAI SECURITY TEST BENCH           ")
    print("==================================================")
    
    try:
        report = bench.run_all()
        print("\n================ RESULTS SUMMARY ================")
        print(f"Total Test Scenarios: {report['total_cases']}")
        print(f"Analysis Accuracy   : {report['accuracy_rate']}%")
        print(f"Average Latency     : {report['average_latency_seconds']}s")
        print(f"RAG Retrieval Rate  : {report['retrieval_rate']}%")
        print(f"Hallucination Rate  : {report['hallucination_rate']}%")
        print("==================================================")
    except Exception as e:
        print(f"\nExecution failed: {e}")
        print("Make sure Ollama is running and gpt-oss is pulled.")

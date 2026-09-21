from typing import List, Dict, Any
from backend.database.chroma_manager import ChromaManager
from backend.config import TOP_K_RETRIEVAL

class KnowledgeAgent:
    """
    Knowledge Agent (RAG).
    Never invents or generates new facts. It is solely responsible for:
    1. Receiving a query.
    2. Searching the ChromaDB vector store.
    3. Retrieving the top K most relevant text chunks.
    4. Returning the raw context and metadata.
    """
    def __init__(self, chroma_manager: ChromaManager = None):
        if chroma_manager is None:
            self.chroma_manager = ChromaManager()
        else:
            self.chroma_manager = chroma_manager

    def retrieve(self, query: str, top_k: int = TOP_K_RETRIEVAL) -> Dict[str, Any]:
        """
        Retrieves relevant context matching the query.
        Returns a dictionary indicating status, the retrieved list of chunks, and combined context text.
        """
        try:
            results = self.chroma_manager.query_documents(query, top_k=top_k)
            
            # Combine the chunks into a single readable block of context
            if results:
                combined_context = "\n\n=== RETRIEVED CONTEXT START ===\n"
                for idx, res in enumerate(results):
                    source = res["metadata"].get("source", "Unknown Source")
                    chunk_idx = res["metadata"].get("chunk_index", 0)
                    score = res.get("score", 0.0)
                    combined_context += (
                        f"[{idx+1}] Source: {source} (Chunk: {chunk_idx}, Relevance Distance: {score:.4f})\n"
                        f"Content:\n{res['text']}\n\n"
                    )
                combined_context += "=== RETRIEVED CONTEXT END ==="
            else:
                combined_context = "No relevant context found in vector database."
                
            return {
                "status": "success",
                "confidence": 1.0,  # Constant 1.0 as it's a direct retrieval, no generation
                "result": {
                    "chunks": results,
                    "combined_context": combined_context
                }
            }
        except Exception as e:
            return {
                "status": "error",
                "confidence": 0.0,
                "error": str(e),
                "result": {
                    "chunks": [],
                    "combined_context": f"Failed to retrieve context: {e}"
                }
            }

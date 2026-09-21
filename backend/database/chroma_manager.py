import json
import urllib.request
import urllib.error
import os
from typing import List, Dict, Any

import chromadb
from chromadb.api.types import Documents, Embeddings, EmbeddingFunction

from backend.config import (
    OLLAMA_API_URL,
    OLLAMA_EMBED_MODEL,
    CHROMA_PERSIST_DIR,
    CHROMA_COLLECTION_NAME
)

class OllamaEmbeddingFunction(EmbeddingFunction):
    """
    Custom ChromaDB Embedding Function that leverages Ollama's embedding API.
    """
    def __init__(self, model_name: str = OLLAMA_EMBED_MODEL, api_url: str = OLLAMA_API_URL):
        self.model_name = model_name
        self.api_url = api_url.rstrip("/")

    def __call__(self, input: Documents) -> Embeddings:
        embeddings = []
        for text in input:
            try:
                # Prepare payload for Ollama's newer /api/embed endpoint
                url = f"{self.api_url}/api/embed"
                payload = {
                    "model": self.model_name,
                    "input": text
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=60) as response:
                    res_data = json.loads(response.read().decode("utf-8"))
                    if "embeddings" in res_data and len(res_data["embeddings"]) > 0:
                        embeddings.append(res_data["embeddings"][0])
                    else:
                        raise ValueError("No embeddings returned from Ollama /api/embed API.")
            except Exception as e:
                # Fallback to older /api/embeddings endpoint if /api/embed fails
                try:
                    url = f"{self.api_url}/api/embeddings"
                    payload = {
                        "model": self.model_name,
                        "prompt": text
                    }
                    req = urllib.request.Request(
                        url,
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=60) as response:
                        res_data = json.loads(response.read().decode("utf-8"))
                        if "embedding" in res_data:
                            embeddings.append(res_data["embedding"])
                        else:
                            raise ValueError("No embedding returned from Ollama /api/embeddings API.")
                except Exception as ex:
                    # Provide a helpful error message if Ollama is not running or model is not pulled
                    raise ConnectionError(
                        f"Failed to generate embedding via Ollama ({e}). "
                        f"Please verify that Ollama is running at {self.api_url} "
                        f"and that you have pulled the embedding model using 'ollama pull {self.model_name}'."
                    ) from ex
        return embeddings

class ChromaManager:
    """
    Manages connection to local ChromaDB vector database, indexing and retrieval.
    """
    def __init__(self):
        # Create storage folder if it doesn't exist
        os.makedirs(CHROMA_PERSIST_DIR, exist_ok=True)
        
        # Initialize persistent client
        self.client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
        self.embedding_function = OllamaEmbeddingFunction()
        
        # Initialize collection
        self.collection = self.client.get_or_create_collection(
            name=CHROMA_COLLECTION_NAME,
            embedding_function=self.embedding_function
        )

    def add_documents(self, chunks: List[Dict[str, Any]]) -> bool:
        """
        Adds pre-processed document chunks to the ChromaDB collection.
        """
        if not chunks:
            return False
            
        ids = []
        documents = []
        metadatas = []
        
        for idx, chunk in enumerate(chunks):
            # Create a unique ID based on file source and index
            source_file = chunk["metadata"]["source"]
            chunk_idx = chunk["metadata"]["chunk_index"]
            safe_source = "".join([c if c.isalnum() else "_" for c in source_file])
            ids.append(f"{safe_source}_chunk_{chunk_idx}")
            documents.append(chunk["text"])
            
            # ChromaDB metadata values must be strings, integers, or floats
            meta = {
                "source": chunk["metadata"]["source"],
                "file_path": chunk["metadata"]["file_path"],
                "chunk_index": chunk_idx,
                "total_chunks": chunk["metadata"]["total_chunks"]
            }
            metadatas.append(meta)
            
        self.collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas
        )
        return True

    def query_documents(self, query_text: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Queries ChromaDB for the most relevant document chunks.
        """
        if not query_text:
            return []
            
        try:
            if self.collection.count() == 0:
                return []
        except Exception:
            pass
            
        # Perform vector search
        results = self.collection.query(
            query_texts=[query_text],
            n_results=top_k
        )
        
        formatted_results = []
        if results and "documents" in results and results["documents"]:
            docs = results["documents"][0]
            metas = results["metadatas"][0] if "metadatas" in results else [{} for _ in docs]
            ids = results["ids"][0] if "ids" in results else ["" for _ in docs]
            distances = results["distances"][0] if "distances" in results else [0.0 for _ in docs]
            
            for i in range(len(docs)):
                formatted_results.append({
                    "id": ids[i],
                    "text": docs[i],
                    "metadata": metas[i],
                    "score": float(distances[i])  # Distance metric (usually L2 distance, lower is more similar)
                })
        return formatted_results

    def get_collection_stats(self) -> Dict[str, Any]:
        """
        Returns stats about the vector database collection.
        """
        try:
            count = self.collection.count()
            return {
                "collection_name": CHROMA_COLLECTION_NAME,
                "document_count": count,
                "status": "healthy"
            }
        except Exception as e:
            return {
                "collection_name": CHROMA_COLLECTION_NAME,
                "document_count": 0,
                "status": "error",
                "error": str(e)
            }

    def clear_collection(self) -> bool:
        """
        Deletes and recreates the collection to wipe all indexed vectors.
        """
        try:
            self.client.delete_collection(name=CHROMA_COLLECTION_NAME)
            self.collection = self.client.get_or_create_collection(
                name=CHROMA_COLLECTION_NAME,
                embedding_function=self.embedding_function
            )
            return True
        except Exception as e:
            print(f"Error resetting database: {e}")
            return False

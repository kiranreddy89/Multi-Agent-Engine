import re
import json
import os
from typing import List, Dict, Any

# Optional imports for PDF and DOCX
try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import docx
except ImportError:
    docx = None

def clean_text(text: str) -> str:
    """
    Cleans text by removing common formatting issues, duplicates,
    normalizing whitespace, and trimming headers/footers.
    """
    if not text:
        return ""
    
    # 1. Normalize line endings and whitespace
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    
    # 2. Remove common header/footer page numbers patterns (e.g. Page 1 of 10, [Page 5])
    text = re.sub(r'(?i)^\s*(page|pg\.?)\s*\d+\s*(of\s*\d+)?\s*$', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\s*\[?\d+\]?\s*$', '', text, flags=re.MULTILINE)
    
    # 3. Clean broken formatting (e.g., continuous hyphens, stars, underscores)
    text = re.sub(r'[-*_~=]{3,}', ' ', text)
    
    # 4. Collapse multiple newlines/whitespaces
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    
    # 5. Remove adjacent exact duplicate lines (common in headers/footers in text extracts)
    lines = text.split("\n")
    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            cleaned_lines.append("")
            continue
        # Avoid duplicating recent non-empty lines
        if cleaned_lines and stripped == cleaned_lines[-1].strip():
            continue
        cleaned_lines.append(line)
        
    return "\n".join(cleaned_lines).strip()

def chunk_text_by_words(text: str, chunk_size: int = 500, overlap: int = 100) -> List[str]:
    """
    Splits text into chunks of specified word count with overlapping.
    """
    words = text.split()
    if len(words) <= chunk_size:
        return [text]
    
    chunks = []
    step = chunk_size - overlap
    if step <= 0:
        step = chunk_size // 2  # Fail-safe overlap
        
    for i in range(0, len(words), step):
        chunk_words = words[i:i + chunk_size]
        chunks.append(" ".join(chunk_words))
        # Stop if we reached the end of the text
        if i + chunk_size >= len(words):
            break
            
    return chunks

def load_file_content(file_path: str) -> str:
    """
    Loads content from PDF, DOCX, MD, TXT, or JSON file.
    """
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext == ".txt" or ext == ".md" or ext == ".markdown":
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
            
    elif ext == ".pdf":
        if pypdf is None:
            raise ImportError("pypdf library is required for PDF parsing. Please install it.")
        reader = pypdf.PdfReader(file_path)
        content_parts = []
        for i, page in enumerate(reader.pages):
            text = page.extract_text()
            if text:
                content_parts.append(text)
        return "\n\n".join(content_parts)
        
    elif ext == ".docx":
        if docx is None:
            raise ImportError("python-docx library is required for DOCX parsing. Please install it.")
        doc = docx.Document(file_path)
        content_parts = [p.text for p in doc.paragraphs]
        return "\n".join(content_parts)
        
    elif ext == ".json":
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            # Pretty-print JSON to make it readable in RAG context
            return json.dumps(data, indent=2)
            
    else:
        # Fallback to general binary text reading
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

def process_file_into_chunks(
    file_path: str, 
    chunk_size: int = 500, 
    overlap: int = 100
) -> List[Dict[str, Any]]:
    """
    Loads a file, cleans it, chunks it, and returns chunk data along with metadata.
    """
    filename = os.path.basename(file_path)
    try:
        raw_text = load_file_content(file_path)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return []
        
    cleaned = clean_text(raw_text)
    chunks = chunk_text_by_words(cleaned, chunk_size, overlap)
    
    chunk_data = []
    for idx, chunk in enumerate(chunks):
        chunk_data.append({
            "text": chunk,
            "metadata": {
                "source": filename,
                "file_path": file_path,
                "chunk_index": idx,
                "total_chunks": len(chunks)
            }
        })
    return chunk_data

from typing import List
import pandas as pd

def create_chunks(text: str, max_tokens: int = 1000) -> List[str]:
    """Split text into chunks of approximately max_tokens"""
    # Simple splitting by sentences for now
    sentences = text.split('. ')
    chunks = []
    current_chunk = []
    current_length = 0
    
    for sentence in sentences:
        # Rough token estimation (words + punctuation)
        sentence_tokens = len(sentence.split()) + 1
        
        if current_length + sentence_tokens > max_tokens and current_chunk:
            chunks.append('. '.join(current_chunk) + '.')
            current_chunk = [sentence]
            current_length = sentence_tokens
        else:
            current_chunk.append(sentence)
            current_length += sentence_tokens
    
    if current_chunk:
        chunks.append('. '.join(current_chunk) + '.')
    
    return chunks

def concatenate_fields(row: pd.Series) -> str:
    """Intelligently concatenate fields into searchable text"""
    # Fields we want to include in the text content
    important_fields = [
        'vulnerability', 'summary', 'remediation_note', 
        'app_and_tech', 'os', 'category', 'software_group'
    ]
    
    parts = []
    for field in important_fields:
        if field in row and pd.notna(row[field]):
            parts.append(f"{field}: {row[field]}")
    
    return "\n".join(parts)
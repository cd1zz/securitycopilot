import pickle
import os
import hashlib
import aiofiles
import logging
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class PickleEmbeddingCache:
    def __init__(self, cache_dir: str = "embedding_cache"):
        """Initialize the embedding cache with pickle backend"""
        self.cache_dir = Path(cache_dir)
        self.cache_file = self.cache_dir / "embeddings.pkl"
        self.cache: Dict[str, List[float]] = {}
        self.cache_dir.mkdir(exist_ok=True)
        
    async def initialize(self):
        """Load the cache from disk if it exists"""
        if self.cache_file.exists():
            try:
                async with aiofiles.open(self.cache_file, 'rb') as f:
                    content = await f.read()
                    self.cache = pickle.loads(content)
                logger.info(f"Loaded {len(self.cache)} embeddings from cache")
            except Exception as e:
                logger.error(f"Failed to load cache: {e}")
                self.cache = {}
    
    def _generate_hash(self, text: str) -> str:
        """Generate a deterministic hash for the input text"""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    async def get_embedding(self, text: str) -> Optional[List[float]]:
        """Retrieve embedding from cache if it exists"""
        text_hash = self._generate_hash(text)
        return self.cache.get(text_hash)
    
    async def store_embedding(self, text: str, embedding: List[float]) -> None:
        """Store embedding in cache"""
        text_hash = self._generate_hash(text)
        self.cache[text_hash] = embedding
        
        # Save to disk immediately (could be optimized to save periodically)
        try:
            async with aiofiles.open(self.cache_file, 'wb') as f:
                await f.write(pickle.dumps(self.cache))
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
    
    async def clear_cache(self) -> None:
        """Clear all cached embeddings"""
        self.cache = {}
        if self.cache_file.exists():
            self.cache_file.unlink()
    
    async def get_cache_stats(self) -> Dict[str, int]:
        """Get statistics about the cache"""
        cache_size = len(pickle.dumps(self.cache)) if self.cache else 0
        return {
            "total_entries": len(self.cache),
            "total_size_bytes": cache_size
        }
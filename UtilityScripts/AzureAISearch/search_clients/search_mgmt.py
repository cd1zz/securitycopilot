import os
import asyncio
import aiohttp
import logging
from typing import Dict, List
import pandas as pd
import uuid
from dotenv import load_dotenv
import time

# Load environment variables from .env file
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CopilotSearchIndex:
    """Index configuration for Security Copilot compatibility"""
    def __init__(self):
        """Initialize index configuration from environment variables"""
        self.name = os.getenv('AZURE_SEARCH_INDEX_NAME', 'security-copilot-index')
        self.openai_endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
        
        if not self.openai_endpoint:
            raise ValueError("AZURE_OPENAI_ENDPOINT environment variable is required")
    
    def generate_timestamp_suffix(self) -> str:
        """Generate timestamp suffix for unique names"""
        return str(int(time.time()))
    
    def to_dict(self) -> dict:
        """Convert to Azure Search index definition"""
        timestamp = self.generate_timestamp_suffix()
        vector_config_name = f"vector-config-{timestamp}"
        vector_profile_name = f"vector-profile-{timestamp}"
        vectorizer_name = f"vectorizer-{timestamp}"
        
        return {
            "name": self.name,
            "fields": [
                {
                    "name": "parent_id",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": True,
                    "retrievable": True,
                    "stored": True,
                    "sortable": True,
                    "facetable": True,
                    "key": False,
                    "analyzer": "standard.lucene",
                    "synonymMaps": []
                },
                {
                    "name": "chunk_id",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": True,
                    "retrievable": True,
                    "stored": True,
                    "sortable": True,
                    "facetable": True,
                    "key": True,
                    "analyzer": "keyword",
                    "synonymMaps": []
                },
                {
                    "name": "title",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": True,
                    "retrievable": True,
                    "stored": True,
                    "sortable": True,
                    "facetable": True,
                    "key": False,
                    "analyzer": "standard.lucene",
                    "synonymMaps": []
                },
                {
                    "name": "chunk",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": False,
                    "retrievable": True,
                    "stored": True,
                    "sortable": False,
                    "facetable": False,
                    "key": False,
                    "analyzer": "standard.lucene",
                    "synonymMaps": []
                },
                {
                    "name": "vector",
                    "type": "Collection(Edm.Single)",
                    "searchable": True,
                    "filterable": False,
                    "retrievable": True,
                    "stored": True,
                    "sortable": False,
                    "facetable": False,
                    "key": False,
                    "dimensions": 1536,
                    "vectorSearchProfile": vector_profile_name,
                    "synonymMaps": []
                },
                {
                    "name": "category",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": True,
                    "retrievable": True,
                    "stored": True,
                    "sortable": True,
                    "facetable": True,
                    "key": False,
                    "analyzer": "standard.lucene",
                    "synonymMaps": []
                }
            ],
            "scoringProfiles": [],
            "suggesters": [],
            "analyzers": [],
            "normalizers": [],
            "tokenizers": [],
            "tokenFilters": [],
            "charFilters": [],
            "similarity": {
                "@odata.type": "#Microsoft.Azure.Search.BM25Similarity"
            },
            "semantic": {
                "configurations": [
                    {
                        "name": "my-semantic-config",
                        "prioritizedFields": {
                            "titleField": {
                                "fieldName": "title"
                            },
                            "prioritizedContentFields": [
                                {
                                    "fieldName": "chunk"
                                }
                            ],
                            "prioritizedKeywordsFields": []
                        }
                    }
                ]
            },
            "vectorSearch": {
                "algorithms": [
                    {
                        "name": vector_config_name,
                        "kind": "hnsw",
                        "hnswParameters": {
                            "metric": "cosine",
                            "m": 4,
                            "efConstruction": 400,
                            "efSearch": 500
                        }
                    }
                ],
                "profiles": [
                    {
                        "name": vector_profile_name,
                        "algorithm": vector_config_name,
                        "vectorizer": vectorizer_name
                    }
                ],
                "vectorizers": [
                    {
                        "name": vectorizer_name,
                        "kind": "azureOpenAI",
                        "azureOpenAIParameters": {
                            "resourceUri": self.openai_endpoint,
                            "deploymentId": os.getenv('AZURE_OPENAI_DEPLOYMENT_ID', 'text-embedding-ada-002'),
                            "apiKey": os.getenv('AZURE_OPENAI_API_KEY')
                        }
                    }
                ],
                "compressions": []
            }
        }

class AsyncCopilotSearchClient:
    """Azure Search client for Security Copilot integration"""
    def __init__(self):
        self.search_service = os.getenv('AZURE_SEARCH_SERVICE')
        self.search_api_key = os.getenv('AZURE_SEARCH_API_KEY')
        self.api_version = "2023-11-01"
        self.openai_endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
        self.openai_api_key = os.getenv('AZURE_OPENAI_API_KEY')
        
        self._validate_env_vars()
        
        self.base_url = f"https://{self.search_service}.search.windows.net"
        self.headers = {
            "Content-Type": "application/json",
            "api-key": self.search_api_key
        }

    def _validate_env_vars(self):
        """Validate required environment variables"""
        required_vars = {
            'AZURE_SEARCH_SERVICE': self.search_service,
            'AZURE_SEARCH_API_KEY': self.search_api_key,
            'AZURE_OPENAI_ENDPOINT': self.openai_endpoint,
            'AZURE_OPENAI_API_KEY': self.openai_api_key,
            'AZURE_OPENAI_DEPLOYMENT_ID': os.getenv('AZURE_OPENAI_DEPLOYMENT_ID')
        }
        
        missing = [k for k, v in required_vars.items() if not v]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

    async def generate_embedding(self, text: str, session: aiohttp.ClientSession) -> List[float]:
        """Generate embeddings using Azure OpenAI"""
        deployment_id = os.getenv('AZURE_OPENAI_DEPLOYMENT_ID', 'text-embedding-ada-002')
        url = f"{self.openai_endpoint}/openai/deployments/{deployment_id}/embeddings?api-version=2023-05-15"
        
        headers = {
            "Content-Type": "application/json",
            "api-key": self.openai_api_key
        }
        
        data = {
            "input": text,
            "model": "text-embedding-ada-002"
        }
        
        async with session.post(url, headers=headers, json=data) as response:
            response.raise_for_status()
            result = await response.json()
            return result['data'][0]['embedding']

    async def create_index(self, config: CopilotSearchIndex) -> None:
        """Create a new search index"""
        url = f"{self.base_url}/indexes?api-version={self.api_version}"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=self.headers, json=config.to_dict()) as response:
                if response.status == 400:
                    error = await response.text()
                    raise ValueError(f"Failed to create index: {error}")
                response.raise_for_status()

    async def upload_documents(self, index_name: str, documents: List[Dict]) -> None:
        """Upload documents to the search index"""
        url = f"{self.base_url}/indexes/{index_name}/docs/index?api-version={self.api_version}"
        actions = [{"@search.action": "upload", **doc} for doc in documents]
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=self.headers, json={"value": actions}) as response:
                if response.status != 200:
                    error = await response.text()
                    raise ValueError(f"Failed to upload documents: {error}")

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

async def process_csv(client: AsyncCopilotSearchClient, config: CopilotSearchIndex, csv_path: str):
    """Process CSV and upload to Azure Search"""
    logger.info(f"Reading CSV file: {csv_path}")
    
    chunk_size = 100
    chunks = pd.read_csv(csv_path, chunksize=chunk_size)
    total_processed = 0
    
    async with aiohttp.ClientSession() as session:
        for chunk_df in chunks:
            documents = []
            for _, row in chunk_df.iterrows():
                # Create the full text from all relevant columns
                text_content = concatenate_fields(row)
                
                # Split into smaller chunks if needed
                text_chunks = create_chunks(text_content)
                parent_id = str(uuid.uuid4())
                
                for i, chunk_text in enumerate(text_chunks):
                    # Generate embedding for this chunk
                    embedding = await client.generate_embedding(chunk_text, session)
                    
                    # Create document
                    doc = {
                        "parent_id": parent_id,
                        "chunk_id": f"{parent_id}-{i}",
                        "title": str(row.get('title', row.get('vulnerability', 'Untitled'))),
                        "chunk": chunk_text,
                        "vector": embedding,
                        "category": str(row.get('category', 'Uncategorized'))
                    }
                    documents.append(doc)
            
            # Upload batch
            await client.upload_documents(config.name, documents)
            total_processed += len(documents)
            logger.info(f"Processed and uploaded {total_processed} documents total")

async def main():
    """Main execution function"""
    try:
        # Verify .env file exists
        if not os.path.exists('.env'):
            logger.error("No .env file found. Please create one with required credentials.")
            logger.info("Required variables: AZURE_SEARCH_SERVICE, AZURE_SEARCH_API_KEY, "
                       "AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_DEPLOYMENT_ID")
            return
        
        # Initialize configuration
        config = CopilotSearchIndex()
        
        # Initialize client
        client = AsyncCopilotSearchClient()
        
        # Create index
        logger.info(f"Creating index: {config.name}")
        await client.create_index(config)
        
        # Process CSV and upload documents
        csv_path = os.getenv('CSV_FILE_PATH', 'data.csv')
        await process_csv(client, config, csv_path)
        
        logger.info("Processing completed successfully")
        
    except Exception as e:
        logger.error(f"Error during execution: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
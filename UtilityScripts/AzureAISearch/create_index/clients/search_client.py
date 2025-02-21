import os
import logging
from typing import Dict, List
import aiohttp
from config.search_index_config import CopilotSearchIndex

logger = logging.getLogger(__name__)

class AsyncCopilotSearchClient:
    """Azure Search client for Security Copilot integration"""
    def __init__(self):
        self.search_service = os.getenv('AZURE_SEARCH_SERVICE')
        self.search_api_key = os.getenv('AZURE_SEARCH_API_KEY')
        self.api_version = os.getenv('AZURE_SEARCH_API_VERSION')
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

    async def skillset_exists(self, skillset_name: str, session: aiohttp.ClientSession) -> bool:
        url = f"{self.base_url}/skillsets/{skillset_name}?api-version={self.api_version}"
        async with session.get(url, headers=self.headers) as response:
            if response.status == 200:
                return True
            elif response.status == 404:
                return False
            else:
                response.raise_for_status()

    async def list_skillsets(self, session: aiohttp.ClientSession) -> list:
        """List all skillsets in the Azure Search service."""
        url = f"{self.base_url}/skillsets?api-version={self.api_version}"
        async with session.get(url, headers=self.headers) as response:
            response.raise_for_status()
            result = await response.json()
            return result.get("value", [])



    async def create_index(self, config: CopilotSearchIndex) -> None:
        """Create a new search index"""
        url = f"{self.base_url}/indexes?api-version={self.api_version}"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=self.headers, json=config.to_dict()) as response:
                if response.status == 400:
                    error = await response.text()
                    raise ValueError(f"Failed to create index: {error}")
                response.raise_for_status()

    async def delete_index(self, index_name: str) -> None:
        """Delete the specified search index."""
        url = f"{self.base_url}/indexes/{index_name}?api-version={self.api_version}"
        async with aiohttp.ClientSession() as session:
            async with session.delete(url, headers=self.headers) as response:
                if response.status not in (200, 204):
                    error = await response.text()
                    raise ValueError(f"Failed to delete index: {error}")


    async def upload_documents(self, index_name: str, documents: List[Dict]) -> None:
        """Upload documents to the search index"""
        url = f"{self.base_url}/indexes/{index_name}/docs/index?api-version={self.api_version}"
        actions = [{"@search.action": "upload", **doc} for doc in documents]
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=self.headers, json={"value": actions}) as response:
                if response.status != 200:
                    error = await response.text()
                    raise ValueError(f"Failed to upload documents: {error}")
import os
from typing import Dict

class CopilotSearchIndex:
    """Index configuration for Security Copilot compatibility"""
    def __init__(self):
        """Initialize index configuration from environment variables"""
        self.name = os.getenv('AZURE_SEARCH_INDEX_NAME', 'security-copilot-index')
        self.openai_endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
        
        if not self.openai_endpoint:
            raise ValueError("AZURE_OPENAI_ENDPOINT environment variable is required")
    
    def to_dict(self) -> Dict:
        """Convert to Azure Search index definition"""
        return {
            "name": self.name,
            "fields": [
                {
                    "name": "parent_id",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": True,
                    "retrievable": True,
                    "sortable": True,
                    "facetable": True,
                    "key": False,
                    "analyzer": "standard.lucene"
                },
                {
                    "name": "chunk_id",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": True,
                    "retrievable": True,
                    "sortable": True,
                    "facetable": True,
                    "key": True,
                    "analyzer": "keyword"
                },
                {
                    "name": "title",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": True,
                    "retrievable": True,
                    "sortable": True,
                    "facetable": True,
                    "key": False,
                    "analyzer": "standard.lucene"
                },
                {
                    "name": "chunk",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": False,
                    "retrievable": True,
                    "sortable": False,
                    "facetable": False,
                    "key": False,
                    "analyzer": "standard.lucene"
                },
                {
                    "name": "vector",
                    "type": "Collection(Edm.Single)",
                    "dimensions": 1536,
                    "vectorSearchProfile": "vector-profile"  
                },
                {
                    "name": "category",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": True,
                    "retrievable": True,
                    "sortable": True,
                    "facetable": True,
                    "key": False,
                    "analyzer": "standard.lucene"
                },
                # New fields
                {
                    "name": "ip_address",
                    "type": "Edm.String",
                    "searchable": True,
                    "filterable": True,
                    "retrievable": True,
                    "sortable": True,
                    "facetable": True,
                    "key": False,
                    "analyzer": "keyword"
                },
                {
                    "name": "has_exploit",
                    "type": "Edm.Boolean",
                    "searchable": False,
                    "filterable": True,
                    "retrievable": True,
                    "sortable": True,
                    "facetable": True,
                    "key": False
                },
                {
                    "name": "is_critical_server",
                    "type": "Edm.Boolean",
                    "searchable": False,
                    "filterable": True,
                    "retrievable": True,
                    "sortable": True,
                    "facetable": True,
                    "key": False
                }
            ],
            "vectorSearch": {
                "algorithms": [
                    {
                        "name": "vector-config",
                        "kind": "hnsw",
                        "hnswParameters": {  
                            "metric": "cosine"
                        }
                    }
                ],
                "vectorizers": [
                    {
                        "name": "vulnerability-vectorizer",
                        "kind": "azureOpenAI",
                        "azureOpenAIParameters": {  
                            "resourceUri": self.openai_endpoint,
                            "deploymentId": os.getenv('AZURE_OPENAI_DEPLOYMENT_ID', 'text-embedding-ada-002'),
                            "modelName": "text-embedding-ada-002",
                            "apiKey": os.getenv('AZURE_OPENAI_API_KEY')
                        }
                    }
                ],
                "profiles": [
                    {
                        "name": "vector-profile",
                        "algorithm": "vector-config",
                        "vectorizer": "vulnerability-vectorizer"
                    }
                ]
            },
            "semantic": {
                "configurations": [
                    {
                        "name": "default",
                        "prioritizedFields": {
                            "titleField": {
                                "fieldName": "title"
                            },
                            "prioritizedContentFields": [
                                {
                                    "fieldName": "chunk"
                                }
                            ],
                            "prioritizedKeywordsFields": [
                                {
                                    "fieldName": "ip_address"
                                },
                                {
                                    "fieldName": "category"
                                }
                            ]
                        }
                    }
                ]
            }
        }
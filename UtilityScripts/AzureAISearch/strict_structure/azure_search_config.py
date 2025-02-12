from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import yaml
import json
from enum import Enum
import os

class FieldType(Enum):
    STRING = "Edm.String"
    INT32 = "Edm.Int32"
    DOUBLE = "Edm.Double"
    BOOLEAN = "Edm.Boolean"
    DATETIME = "Edm.DateTimeOffset"
    VECTOR = "Collection(Edm.Single)"

@dataclass
class SearchField:
    name: str
    field_type: FieldType
    searchable: bool = False
    filterable: bool = False
    sortable: bool = False
    facetable: bool = False
    key: bool = False
    retrievable: bool = True
    dimensions: Optional[int] = None
    vector_search_profile: Optional[str] = None

@dataclass
class VectorSearchConfig:
    algorithm_name: str = "vector-config"
    metric: str = "cosine"
    m: int = 4
    ef_construction: int = 400
    ef_search: int = 500
    profile_name: str = "vector-profile"
    vectorizer_name: str = "vectorizer"
    vectorizer_deployment_id: str = "text-embedding-ada-002"
    vectorizer_model_name: str = "text-embedding-ada-002"

@dataclass
class IndexConfig:
    name: str
    fields: List[SearchField]
    vector_search: Optional[VectorSearchConfig] = None
    embedding_fields: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert the index configuration to Azure Search format"""
        fields = []
        for field in self.fields:
            field_dict = {
                "name": field.name,
                "type": field.field_type.value,
                "searchable": field.searchable,
                "filterable": field.filterable,
                "sortable": field.sortable,
                "facetable": field.facetable,
                "key": field.key,
                "retrievable": field.retrievable
            }
            
            if field.field_type == FieldType.VECTOR:
                field_dict.update({
                    "dimensions": field.dimensions,
                    "vectorSearchProfile": field.vector_search_profile
                })
            
            fields.append(field_dict)

        index_def = {
            "name": self.name,
            "fields": fields
        }

        if self.vector_search:
            index_def["vectorSearch"] = {
                "algorithms": [{
                    "name": self.vector_search.algorithm_name,
                    "kind": "hnsw",
                    "hnswParameters": {
                        "metric": self.vector_search.metric,
                        "m": self.vector_search.m,
                        "efConstruction": self.vector_search.ef_construction,
                        "efSearch": self.vector_search.ef_search
                    }
                }],
                "profiles": [{
                    "name": self.vector_search.profile_name,
                    "algorithm": self.vector_search.algorithm_name,
                    "vectorizer": self.vector_search.vectorizer_name
                }],
                "vectorizers": [{
                    "name": self.vector_search.vectorizer_name,
                    "kind": "azureOpenAI",
                    "azureOpenAIParameters": {
                        "resourceUri": os.getenv('AZURE_OPENAI_ENDPOINT'),
                        "deploymentId": self.vector_search.vectorizer_deployment_id,
                        "apiKey": os.getenv('AZURE_OPENAI_API_KEY'),
                        "modelName": self.vector_search.vectorizer_model_name
                    }
                }]
            }

        return index_def

    @classmethod
    def from_yaml(cls, file_path: str) -> 'IndexConfig':
        """Load index configuration from a YAML file"""
        with open(file_path, 'r') as f:
            config = yaml.safe_load(f)
            
        fields = []
        for field_config in config['fields']:
            fields.append(SearchField(
                name=field_config['name'],
                field_type=FieldType(field_config['type']),
                searchable=field_config.get('searchable', False),
                filterable=field_config.get('filterable', False),
                sortable=field_config.get('sortable', False),
                facetable=field_config.get('facetable', False),
                key=field_config.get('key', False),
                retrievable=field_config.get('retrievable', True),
                dimensions=field_config.get('dimensions'),
                vector_search_profile=field_config.get('vector_search_profile')
            ))
            
        vector_search = None
        if 'vector_search' in config:
            vc = config['vector_search']
            vector_search = VectorSearchConfig(
                algorithm_name=vc.get('algorithm_name', "vector-config"),
                metric=vc.get('metric', "cosine"),
                m=vc.get('m', 4),
                ef_construction=vc.get('ef_construction', 400),
                ef_search=vc.get('ef_search', 500),
                profile_name=vc.get('profile_name', "vector-profile"),
                vectorizer_name=vc.get('vectorizer_name', "vectorizer"),
                vectorizer_deployment_id=vc.get('vectorizer_deployment_id', "text-embedding-ada-002"),
                vectorizer_model_name=vc.get('vectorizer_model_name', "text-embedding-ada-002")
            )
            
        return cls(
            name=config['name'],
            fields=fields,
            vector_search=vector_search,
            embedding_fields=config.get('embedding_fields', [])
        )

# Example usage:
if __name__ == "__main__":
    # Example of how to create a configuration programmatically
    fields = [
        SearchField("id", FieldType.STRING, key=True, sortable=True),
        SearchField("title", FieldType.STRING, searchable=True, retrievable=True),
        SearchField("embedding", FieldType.VECTOR, dimensions=1536, 
                   vector_search_profile="vector-profile")
    ]
    
    vector_config = VectorSearchConfig(
        algorithm_name="vector-config",
        profile_name="vector-profile"
    )
    
    config = IndexConfig(
        name="sample-index",
        fields=fields,
        vector_search=vector_config,
        embedding_fields=["title"]
    )
    
    # Save configuration
    with open('index_config.yaml', 'w') as f:
        yaml.dump({
            'name': config.name,
            'fields': [{
                'name': field.name,
                'type': field.field_type.value,
                'searchable': field.searchable,
                'filterable': field.filterable,
                'sortable': field.sortable,
                'facetable': field.facetable,
                'key': field.key,
                'retrievable': field.retrievable,
                'dimensions': field.dimensions,
                'vector_search_profile': field.vector_search_profile
            } for field in config.fields],
            'vector_search': {
                'algorithm_name': config.vector_search.algorithm_name,
                'metric': config.vector_search.metric,
                'm': config.vector_search.m,
                'ef_construction': config.vector_search.ef_construction,
                'ef_search': config.vector_search.ef_search,
                'profile_name': config.vector_search.profile_name,
                'vectorizer_name': config.vector_search.vectorizer_name,
                'vectorizer_deployment_id': config.vector_search.vectorizer_deployment_id,
                'vectorizer_model_name': config.vector_search.vectorizer_model_name
            } if config.vector_search else None,
            'embedding_fields': config.embedding_fields
        }, f)
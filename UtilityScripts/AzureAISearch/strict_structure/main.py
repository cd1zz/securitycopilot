import os
import asyncio
import aiohttp
import aioconsole 
import pandas as pd
from typing import List, Dict, Any, Iterator, Optional
import os
from dotenv import load_dotenv
import uuid
from datetime import datetime
import openai
import logging
from embedding_cache import PickleEmbeddingCache
from azure_search_config import IndexConfig, SearchField, FieldType, VectorSearchConfig

# Load environment variables
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AsyncAzureSearchClient:
    def __init__(self):
        """Initialize the client using environment variables"""
        # Azure AI Search configuration
        self.search_service = os.getenv('AZURE_SEARCH_SERVICE')
        self.search_api_key = os.getenv('AZURE_SEARCH_API_KEY')
        self.search_api_version = os.getenv('AZURE_SEARCH_API_VERSION', "2024-11-01-preview")
        
        # Azure OpenAI configuration
        self.openai_endpoint = os.getenv('AZURE_OPENAI_ENDPOINT')
        self.openai_api_key = os.getenv('AZURE_OPENAI_API_KEY')
        self.openai_api_version = os.getenv('AZURE_OPENAI_API_VERSION', "2023-05-15")
        self.openai_deployment_id = os.getenv('AZURE_OPENAI_DEPLOYMENT_ID')
        self.openai_model = os.getenv('AZURE_OPENAI_MODEL')

        # Validate required environment variables
        required_vars = {
            'AZURE_SEARCH_SERVICE': self.search_service,
            'AZURE_SEARCH_API_KEY': self.search_api_key,
            'AZURE_OPENAI_ENDPOINT': self.openai_endpoint,
            'AZURE_OPENAI_API_KEY': self.openai_api_key,
            'AZURE_OPENAI_DEPLOYMENT_ID': self.openai_deployment_id,
            'AZURE_OPENAI_MODEL': self.openai_model
        }
        
        missing_vars = [var for var, value in required_vars.items() if not value]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
                
        # Construct the base URL using the service name
        self.base_url = f"https://{self.search_service}.search.windows.net"
        self.headers = {
            "Content-Type": "application/json",
            "api-key": self.search_api_key
        }
            
        # Configure OpenAI
        openai.api_type = "azure"
        openai.api_version = self.openai_api_version  # Using OpenAI-specific version
        openai.api_base = self.openai_endpoint
        openai.api_key = self.openai_api_key

        # Initialize cache
        self.embedding_cache = PickleEmbeddingCache()
        
    async def initialize(self):
        """Initialize cache and verify credentials"""
        # Initialize cache first
        await self.embedding_cache.initialize()
        
        # Then verify credentials
        await self.verify_credentials()

    async def generate_embedding(self, text: str, session: aiohttp.ClientSession) -> List[float]:
        """Generate embeddings using Azure OpenAI"""
        # Use the OpenAI endpoint directly
        url = f"{self.openai_endpoint}/openai/deployments/{os.getenv('AZURE_OPENAI_DEPLOYMENT_ID')}/embeddings?api-version={self.openai_api_version}"
        
        headers = {
            "Content-Type": "application/json",
            "api-key": self.openai_api_key  # Use OpenAI key, not search key
        }
        
        
        data = {
            "input": text,
            "model": os.getenv('AZURE_OPENAI_MODEL', 'text-embedding-ada-002')
        }
        
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                async with session.post(url, headers=headers, json=data) as response:
                    if response.status == 429:  # Rate limit
                        retry_after = int(response.headers.get('Retry-After', retry_delay))
                        await asyncio.sleep(retry_after)
                        continue
                        
                    response.raise_for_status()
                    result = await response.json()
                    return result['data'][0]['embedding']
                    
            except Exception as e:
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(retry_delay * (2 ** attempt))

    async def generate_document_embedding(self, doc: Dict[str, Any], embedding_fields: List[str], session: aiohttp.ClientSession) -> List[float]:
            """Generate embeddings for a document by combining specified fields"""
            fields_to_embed = []
            for field in embedding_fields:
                value = doc.get(field)
                if value is not None:
                    fields_to_embed.append(f"{field}: {value}")
            
            combined_text = " ".join([str(field) for field in fields_to_embed if field])
            
            # Try to get embedding from cache first
            cached_embedding = await self.embedding_cache.get_embedding(combined_text)
            if cached_embedding is not None:
                logger.debug("Using cached embedding")
                return cached_embedding
                
            # Generate new embedding if not in cache
            logger.debug("Generating new embedding")
            embedding = await self.generate_embedding(combined_text, session)
            
            # Store in cache for future use
            await self.embedding_cache.store_embedding(combined_text, embedding)
            
            return embedding

    async def batch_generate_embeddings(self, documents: List[Dict[str, Any]], embedding_fields: List[str], batch_size: int = 10) -> List[Dict[str, Any]]:
            """Generate embeddings for documents in batches asynchronously"""
            embedded_documents = []
            total_docs = len(documents)
            cache_hits = 0
            
            logger.info(f"Starting embedding generation for {total_docs} documents")
            
            async with aiohttp.ClientSession() as session:
                async def process_doc(doc):
                    nonlocal cache_hits
                    try:
                        embedding = await self.generate_document_embedding(doc, embedding_fields, session)
                        if embedding:
                            doc['embedding'] = embedding
                            return doc
                    except Exception as e:
                        logger.error(f"Error processing document {doc.get('id')}: {str(e)}")
                        return None
                
                tasks = [process_doc(doc) for doc in documents]
                results = await asyncio.gather(*tasks)
                embedded_documents = [doc for doc in results if doc is not None]
            
            # Log cache statistics
            cache_stats = await self.embedding_cache.get_cache_stats()
            logger.info(f"Cache statistics: {cache_stats}")
            
            return embedded_documents
    
    async def create_index(self, config: IndexConfig, force: bool = False) -> dict:
        """Create a new search index using Azure AI Search"""
        url = f"{self.base_url}/indexes?api-version={self.search_api_version}"
        
        # Get environment variables for OpenAI configuration
        if not os.getenv('AZURE_OPENAI_ENDPOINT') or not os.getenv('AZURE_OPENAI_API_KEY'):
            raise ValueError("Missing OpenAI configuration in environment variables")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=self.headers, json=config.to_dict()) as response:
                if response.status == 400:
                    error_content = await response.text()
                    logger.info(f"Error response: {error_content}")
                    # Don't raise error here, let calling code handle it
                    return {"error": error_content}
                response.raise_for_status()
                return await response.json()

    async def upload_documents(self, index_name: str, documents: List[Dict[str, Any]], batch_size: int = 1000) -> List[dict]:
        """Upload documents to the search index in batches asynchronously"""
        url = f"{self.base_url}/indexes/{index_name}/docs/index?api-version={self.search_api_version}"
        results = []
        sem = asyncio.Semaphore(5)  # Limit concurrent uploads
        
        async def upload_batch(batch):
            async with sem:
                # Validate and prepare documents
                actions = []
                for doc in batch:
                    if not doc.get("id"):
                        logger.error(f"Document missing required 'id' field: {doc}")
                        continue
                        
                    cleaned_doc = {k: v for k, v in doc.items() if v is not None}
                    action = {
                        "@search.action": "upload",
                        **cleaned_doc
                    }
                    actions.append(action)
                
                if not actions:
                    logger.error("No valid documents to upload in batch")
                    return {"error": "No valid documents"}
                
                request_body = {"value": actions}
                
                async with aiohttp.ClientSession() as session:
                    try:
                        async with session.post(url, headers=self.headers, json=request_body) as response:
                            response_text = await response.text()
                            
                            try:
                                response_json = await response.json()
                                
                                if response.status == 200:
                                    # Count successful operations - look for status: True and statusCode: 201
                                    successful = len([r for r in response_json.get('value', []) 
                                                if r.get('status') is True and r.get('statusCode') == 201])
                                    logger.info(f"Successfully uploaded {successful} documents in this batch")
                                    return {"status": "success", "count": successful, "response": response_json}
                                else:
                                    logger.error(f"Upload failed with status {response.status}: {response_text}")
                                    return {"error": f"Upload failed: {response_text}"}
                                    
                            except Exception as e:
                                logger.error(f"Failed to parse response as JSON: {str(e)}")
                                return {"error": f"JSON parse error: {str(e)}"}
                                
                    except Exception as e:
                        logger.error(f"Exception during upload: {str(e)}")
                        return {"error": str(e)}
        
        tasks = []
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            tasks.append(upload_batch(batch))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        total_successful = 0
        successful_results = []
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Batch upload failed with exception: {str(result)}")
            elif isinstance(result, dict):
                if "error" in result:
                    logger.error(f"Batch upload failed: {result['error']}")
                else:
                    successful_results.append(result)
                    total_successful += result.get("count", 0)
        
        logger.info(f"Batch upload complete. Total documents successfully uploaded: {total_successful}")
        return successful_results
    
    async def verify_credentials(self):
        """Verify both Azure AI Search and Azure OpenAI credentials"""
        # Verify Azure AI Search credentials
        search_url = f"{self.base_url}/indexes?api-version={self.search_api_version}"
        
        logger.info("Verifying Azure AI Search credentials...")
        async with aiohttp.ClientSession() as session:
            async with session.get(search_url, headers=self.headers) as response:
                if response.status == 403:
                    logger.info("Azure AI Search Authentication Failed")
                    response_text = await response.text()
                    logger.info(f"Response: {response_text}")
                response.raise_for_status()
                
        # Verify Azure OpenAI credentials
        logger.info("Verifying Azure OpenAI credentials...")
        try:
            async with aiohttp.ClientSession() as session:
                # Try to generate a test embedding
                await self.generate_embedding("test", session)
            logger.info("Azure OpenAI Authentication Successful")
        except Exception as e:
            logger.info(f"Azure OpenAI Authentication Failed: {str(e)}")
            raise

    async def index_exists(self, index_name: str) -> bool:
        """Check if an index exists"""
        url = f"{self.base_url}/indexes/{index_name}?api-version={self.search_api_version}"
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=self.headers) as response:
                    return response.status == 200
            except Exception as e:
                logger.error(f"Error checking index existence: {str(e)}")
                raise

    async def delete_index(self, index_name: str) -> None:
        """Delete an existing index"""
        url = f"{self.base_url}/indexes/{index_name}?api-version={self.search_api_version}"
        
        async with aiohttp.ClientSession() as session:
            async with session.delete(url, headers=self.headers) as response:
                if response.status != 204:
                    error_content = await response.text()
                    logger.error(f"Error deleting index: {error_content}")
                    response.raise_for_status()
                logger.info(f"Successfully deleted index '{index_name}'")

def process_csv_data(csv_file: str, config: IndexConfig, batch_size: int = 1000) -> Iterator[List[Dict[str, Any]]]:
    """
    Process CSV data based on the index configuration, yielding batches of documents.
    
    Args:
        csv_file: Path to the CSV file
        config: IndexConfig object containing field configurations
        batch_size: Number of records to process in each batch
        
    Yields:
        Batches of documents ready for indexing
    """
    import csv
    from datetime import datetime
    
    def convert_to_iso_datetime(value: Any) -> Optional[str]:
        """Convert datetime to ISO 8601 format with UTC timezone"""
        if pd.isna(value):
            return None
        try:
            # Convert to pandas timestamp first
            ts = pd.to_datetime(value)
            # Convert to UTC and format properly
            return ts.tz_localize('UTC').isoformat()
        except Exception as e:
            logger.warning(f"Error converting datetime value '{value}': {str(e)}")
            return None

    # Initialize type handling
    converters = {}
    dtype_map = {}

    for field in config.fields:
        field_name = field.name.lower()
        if field.field_type == FieldType.BOOLEAN:
            converters[field_name] = lambda x: str(x).lower() in ['true', 'yes', '1', 't', 'y']
        else:
            # Read everything else as string initially
            dtype_map[field_name] = 'str'

    # Configuration for pandas read_csv
    csv_options = {
        'chunksize': batch_size,
        'encoding': 'utf-8',
        'encoding_errors': 'replace',
        'on_bad_lines': 'warn',
        'low_memory': False,
        'dtype': dtype_map,
        'converters': converters,
        'quoting': csv.QUOTE_ALL,  # Handle all fields as quoted
        'skipinitialspace': True,  # Skip spaces after delimiters
        'na_values': ['', '#N/A', '#N/A N/A', '#NA', '-1.#IND', '-1.#QNAN', 
                     '-NaN', '-nan', '1.#IND', '1.#QNAN', 'N/A', 'NA', 'NULL', 
                     'NaN', 'nan', 'null']  # Comprehensive NA handling
    }

    processed_rows = set()  # Track processed rows
    logger.info(f"Starting CSV processing with batch size {batch_size}")

    try:
        chunks = pd.read_csv(csv_file, **csv_options)
    except UnicodeDecodeError:
        logger.info("UTF-8 failed, attempting with cp1252 encoding...")
        csv_options['encoding'] = 'cp1252'
        chunks = pd.read_csv(csv_file, **csv_options)

    for chunk_df in chunks:
        try:
            # Convert column names to snake_case
            chunk_df.columns = [col.lower().replace(' ', '_') for col in chunk_df.columns]
            
            documents = []
            for idx, row in chunk_df.iterrows():
                try:
                    # Skip if we've seen this row before
                    if idx in processed_rows:
                        continue
                    processed_rows.add(idx)
                    
                    doc = {"id": str(uuid.uuid4())}  # Always include ID
                    
                    for field in config.fields:
                        if field.name == 'id':
                            continue
                            
                        csv_col = field.name.lower()
                        if csv_col not in chunk_df.columns:
                            continue
                        
                        value = row[csv_col]
                        
                        # Skip None/NaN values
                        if pd.isna(value):
                            continue
                            
                        # Handle different field types
                        try:
                            if field.field_type == FieldType.INT32:
                                # Handle potential floating point numbers
                                doc[field.name] = int(float(value))
                            elif field.field_type == FieldType.DOUBLE:
                                doc[field.name] = float(value)
                            elif field.field_type == FieldType.BOOLEAN:
                                # Boolean conversion already handled by converter
                                doc[field.name] = value
                            elif field.field_type == FieldType.DATETIME:
                                iso_date = convert_to_iso_datetime(value)
                                if iso_date:
                                    doc[field.name] = iso_date
                            elif field.field_type == FieldType.STRING:
                                # Ensure string and strip whitespace
                                doc[field.name] = str(value).strip()
                            elif field.field_type == FieldType.VECTOR:
                                continue  # Skip vector fields, handled elsewhere
                        except (ValueError, TypeError) as e:
                            logger.warning(f"Error converting {field.name} value '{value}': {str(e)}")
                            continue
                    
                    documents.append(doc)
                except Exception as row_error:
                    logger.error(f"Error processing row {idx}: {str(row_error)}")
                    continue
            
            if documents:
                logger.info(f"Processed batch of {len(documents)} documents")
                yield documents
                
        except Exception as chunk_error:
            logger.error(f"Error processing chunk: {str(chunk_error)}")
            continue

async def main():
    """Main execution function with enhanced index handling"""
    try:
        # Load the configuration from YAML
        config_path = os.getenv('SEARCH_CONFIG_PATH', 'vulnerability-search-index-config.yaml')
        logger.info(f"Loading index configuration from {config_path}...")
        config = IndexConfig.from_yaml(config_path)
        
        # Initialize the client
        logger.info("Initializing Azure Search client...")
        client = AsyncAzureSearchClient()
        await client.initialize()
        
        # Check if index exists and handle accordingly
        logger.info(f"Checking if index '{config.name}' exists...")
        index_exists = await client.index_exists(config.name)
        
        proceed_with_creation = True
        if index_exists:
            logger.info(f"Index '{config.name}' already exists.")
            response = await aioconsole.ainput(
                "Index already exists. Would you like to:\n"
                "1. Skip index creation and proceed with data upload\n"
                "2. Delete existing index and create new one\n"
                "3. Exit\n"
                "Please enter 1, 2, or 3: "
            )
            
            if response == "1":
                logger.info("Proceeding with data upload using existing index...")
                proceed_with_creation = False
            elif response == "2":
                logger.info("Deleting existing index...")
                await client.delete_index(config.name)
                proceed_with_creation = True
            else:
                logger.info("Exiting as requested.")
                return
        
        if proceed_with_creation:
            logger.info(f"Creating index '{config.name}'...")
            result = await client.create_index(config)
            if isinstance(result, dict) and "error" in result:
                logger.error(f"Failed to create index: {result['error']}")
                return
        
        # Process the CSV data in batches
        logger.info("Starting CSV processing...")
        csv_file = os.getenv('CSV_FILE_PATH', 'vulnerability_data.csv')
        total_processed = 0
        total_uploaded = 0
        batch_size = int(os.getenv('BATCH_SIZE', '1000'))
        
        # Get total rows using pandas
        try:
            logger.info("Counting total rows in CSV file...")
            # Read with the same parameters as the main processing
            df = pd.read_csv(csv_file, 
                            encoding='utf-8',
                            encoding_errors='replace',
                            dtype=str)  # Use consistent dtype
            total_rows = len(df)
            logger.info(f"Found {total_rows:,} rows to process")
        except Exception as e:
            logger.error(f"Error counting rows: {str(e)}")
            logger.info("Continuing without total row count...")
            total_rows = None
        
        for batch in process_csv_data(csv_file, config, batch_size=batch_size):
            total_processed += len(batch)
            
            if total_rows:
                progress = f"{total_processed:,}/{total_rows:,} rows ({(total_processed/total_rows)*100:.1f}%)"
            else:
                progress = f"{total_processed:,} rows"
                
            logger.info(f"Processing batch... Progress: {progress}")
            
            try:
                # Generate embeddings if configured
                if config.vector_search and config.embedding_fields:
                    logger.info(f"Generating embeddings for batch of {len(batch)} documents...")
                    logger.info(f"Using fields for embedding: {config.embedding_fields}")
                    batch_with_embeddings = await client.batch_generate_embeddings(
                        batch,
                        config.embedding_fields,
                        batch_size=10
                    )
                else:
                    batch_with_embeddings = batch
                    logger.info("Skipping embeddings generation (not configured in YAML)")
                
                # Upload batch
                logger.info(f"Uploading batch of {len(batch_with_embeddings)} documents to Azure Search...")
                upload_results = await client.upload_documents(config.name, batch_with_embeddings)
                
                # Count successful uploads
                successful_uploads = sum(result.get("count", 0) for result in upload_results 
                                    if isinstance(result, dict) and "count" in result)
                
                total_uploaded += successful_uploads
                
                logger.info(f"Successfully uploaded {successful_uploads} documents in this batch")
                logger.info(f"Total documents uploaded so far: {total_uploaded:,}")
                
            except Exception as batch_error:
                logger.error(f"Error processing batch: {str(batch_error)}")
                logger.error("Continuing with next batch...")
                continue
        
        # Final summary
        logger.info("Processing completed!")
        logger.info(f"Total rows processed: {total_processed:,}")
        logger.info(f"Total documents uploaded: {total_uploaded:,}")
        
        if total_uploaded < total_processed:
            logger.warning(f"Note: {total_processed - total_uploaded:,} documents failed to upload")
        
        # Cache statistics if using embeddings
        if config.vector_search and config.embedding_fields:
            cache_stats = await client.embedding_cache.get_cache_stats()
            logger.info(f"Embedding cache statistics: {cache_stats}")
        
    except FileNotFoundError as e:
        logger.error(f"Configuration or CSV file not found: {str(e)}")
        raise
    except ValueError as e:
        logger.error(f"Configuration error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error during execution: {str(e)}")
        raise
    finally:
        logger.info("Script execution completed.")


if __name__ == "__main__":
    asyncio.run(main())
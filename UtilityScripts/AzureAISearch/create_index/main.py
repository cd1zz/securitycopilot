import os
import asyncio
import logging
import uuid
import pandas as pd
import aiohttp
from dotenv import load_dotenv
from config.search_index_config import CopilotSearchIndex
from clients.search_client import AsyncCopilotSearchClient
from utils.text_processing import create_chunks, concatenate_fields

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def process_csv(client: AsyncCopilotSearchClient, config: CopilotSearchIndex, csv_path: str):
    """Process CSV and upload to Azure Search"""
    logger.info(f"Reading CSV file: {csv_path}")
    
    chunk_size = 100
    chunks = pd.read_csv(csv_path, chunksize=chunk_size)
    total_processed = 0
    
    async with aiohttp.ClientSession() as session:
        # Enumerate all skillsets and check if any is configured for our index.
        skillsets = await client.list_skillsets(session)
        embedding_needed = True
        for skillset in skillsets:
            if "indexProjections" in skillset and "selectors" in skillset["indexProjections"]:
                for selector in skillset["indexProjections"]["selectors"]:
                    if selector.get("targetIndexName") == config.name:
                        embedding_needed = False
                        logger.info(f"Found skillset '{skillset['name']}' configured for index '{config.name}'. Skipping embedding generation.")
                        break
                if not embedding_needed:
                    break

        logger.info(f"No Azure skillsets found, generating embeddings on our own.")
        for chunk_df in chunks:
            documents = []
            for _, row in chunk_df.iterrows():
                # Create the full text from all relevant columns.
                text_content = concatenate_fields(row)
                
                # Split into smaller chunks if needed.
                text_chunks = create_chunks(text_content)
                parent_id = str(uuid.uuid4())
                
                for i, chunk_text in enumerate(text_chunks):
                    if embedding_needed:
                        embedding = await client.generate_embedding(chunk_text, session)
                    else:
                        embedding = None
                        
                    # Create document with new fields included
                    doc = {
                        "parent_id": parent_id,
                        "chunk_id": f"{parent_id}-{i}",
                        "title": str(row.get('title', row.get('vulnerability', 'Untitled'))),
                        "chunk": chunk_text,
                        "category": str(row.get('category', 'Uncategorized')),
                        # Add new fields with appropriate type conversion
                        "ip_address": str(row.get('ip_address', '')),
                        "has_exploit": bool(row.get('has_exploit', False)),
                        "is_critical_server": bool(row.get('is_critical_server', False))
                    }
                    
                    if embedding_needed:
                        doc["vector"] = embedding
                    documents.append(doc)
            
            # Upload batch.
            await client.upload_documents(config.name, documents)
            total_processed += len(documents)
            logger.info(f"Processed and uploaded {total_processed} documents total")


async def main():
    """Main execution function"""
    try:
        load_dotenv()
        
        if not os.path.exists('.env'):
            logger.error("No .env file found. Please create one with required credentials.")
            logger.info("Required variables: AZURE_SEARCH_SERVICE, AZURE_SEARCH_API_KEY, "
                        "AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_DEPLOYMENT_ID")
            return
        
        config = CopilotSearchIndex()
        client = AsyncCopilotSearchClient()
        
        logger.info(f"Creating index: {config.name}")
        try:
            await client.create_index(config)
        except ValueError as e:
            error_text = str(e)
            if "ResourceNameAlreadyInUse" in error_text:
                while True:
                    user_choice = input(f"Index '{config.name}' already exists. Options: re-create (r), delete (d), continue (c), or exit (e): ")
                    if user_choice.lower() == 'r':
                        logger.info(f"Deleting index '{config.name}' for re-creation.")
                        await client.delete_index(config.name)
                        logger.info(f"Recreating index: {config.name}")
                        await client.create_index(config)
                        break
                    elif user_choice.lower() == 'd':
                        logger.info(f"Deleting index '{config.name}'. Exiting program after deletion.")
                        await client.delete_index(config.name)
                        return
                    elif user_choice.lower() == 'c':
                        logger.info(f"Continuing with existing index: {config.name}")
                        break
                    elif user_choice.lower() == 'e':
                        logger.info("Exiting program.")
                        return
                    else:
                        print("Invalid option. Please choose 'r', 'd', 'c', or 'e'.")
            else:
                raise
        
        csv_path = os.getenv('CSV_FILE_PATH', 'data.csv')
        await process_csv(client, config, csv_path)
        logger.info("Processing completed successfully")
        
    except Exception as e:
        logger.error(f"Error during execution: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
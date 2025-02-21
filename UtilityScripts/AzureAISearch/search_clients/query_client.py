import os
import asyncio
import aiohttp
import json
from typing import Dict, Any, Optional
from dotenv import load_dotenv
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AsyncAzureSearchClient:
    def __init__(self):
        """Initialize the client using environment variables"""
        # Load environment variables
        load_dotenv()
        
        # Azure AI Search configuration
        self.search_service = os.getenv('AZURE_SEARCH_SERVICE')
        self.search_api_key = os.getenv('AZURE_SEARCH_API_KEY')
        self.search_api_version = os.getenv('AZURE_SEARCH_API_VERSION')
        
        # Validate required environment variables
        if not self.search_service or not self.search_api_key:
            raise ValueError("Missing required environment variables: AZURE_SEARCH_SERVICE, AZURE_SEARCH_API_KEY")
                
        # Construct the base URL using the service name
        self.base_url = f"https://{self.search_service}.search.windows.net"
        self.headers = {
            "Content-Type": "application/json",
            "api-key": self.search_api_key
        }

    async def search(self, index_name: str, search_query: str, 
                    filter_query: Optional[str] = None,
                    select: Optional[str] = None,
                    top: int = 10) -> Dict[str, Any]:
        """Perform a search query on the specified index."""
        url = f"{self.base_url}/indexes/{index_name}/docs/search?api-version={self.search_api_version}"
        
        # Build the search request
        request_body = {
            "count": True,
            "top": top
        }

        # Handle search query
        if search_query and search_query != "*":
            request_body["search"] = search_query
            request_body["queryType"] = "full"
        else:
            request_body["search"] = "*"
            
        if filter_query:
            request_body["filter"] = filter_query
            
        if select:
            request_body["select"] = select

        logger.debug(f"Request body: {json.dumps(request_body, indent=2)}")

        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(url, headers=self.headers, json=request_body) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"Search request failed with status {response.status}")
                        logger.error(f"Error details: {error_text}")
                        raise aiohttp.ClientResponseError(
                            response.request_info,
                            response.history,
                            status=response.status,
                            message=f"Search request failed: {error_text}"
                        )
                    return await response.json()
            except Exception as e:
                logger.error(f"Error during search request: {str(e)}")
                raise

async def format_result(doc: Dict[str, Any], index: int) -> str:
    """Format a single search result for display"""
    # Fields to exclude from display
    exclude_fields = {'embedding', '@search.score'}
    
    # Fields to show first in this order
    priority_fields = [
        'id', 'vulnerability', 'category', 'summary', 
        'is_critical_server', 'has_exploit', 'os', 
        'ola_priority', 'remediation_note'
    ]
    
    output = []
    output.append(f"\nResult {index}:")
    output.append("=" * 80)
    
    # Add priority fields first
    for field in priority_fields:
        if field in doc:
            value = doc[field]
            # Format datetime strings
            if isinstance(value, str) and 'T' in value and value.endswith('Z'):
                try:
                    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    value = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                except ValueError:
                    pass
            # Highlight certain fields
            if field in {'is_critical_server', 'has_exploit'} and value is True:
                value = f"*** {value} ***"
            output.append(f"{field:.<40} {value}")
    
    # Add remaining fields
    remaining_fields = sorted(set(doc.keys()) - set(priority_fields) - exclude_fields)
    if remaining_fields:
        output.append("\nAdditional Information:")
        output.append("-" * 40)
        for field in remaining_fields:
            value = doc[field]
            # Format datetime strings
            if isinstance(value, str) and 'T' in value and value.endswith('Z'):
                try:
                    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    value = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                except ValueError:
                    pass
            output.append(f"{field:.<40} {value}")
    
    return "\n".join(output)

async def display_results(results: Dict[str, Any], query_info: Dict[str, Any]):
    """Display search results in a formatted way"""
    print("\nQuery Information:")
    print("=" * 80)
    print(f"Filter Query.....: {query_info.get('filter', 'None')}")
    print(f"Search Query....: {query_info.get('search', '*')}")
    print(f"Selected Fields.: {query_info.get('fields', 'all')}")
    print(f"Max Results....: {query_info.get('top', 10)}")
    
    if 'value' not in results:
        print("\nNo results returned. Check your query syntax.")
        return
    
    if not results['value']:
        print("\nNo matching documents found.")
        return
    
    total_count = results.get('@odata.count', len(results['value']))
    print(f"\nFound {total_count} matching documents")
    print("=" * 80)
    
    for i, doc in enumerate(results['value'], 1):
        print(await format_result(doc, i))
    
    print("\n" + "=" * 80)
    print(f"Total Results: {total_count}")

async def main():
    """Main function to handle user interaction"""
    try:
        client = AsyncAzureSearchClient()
        index_name = os.getenv('AZURE_SEARCH_INDEX_NAME')
        
        print("\nAzure AI Search Query Tool")
        print("=" * 30)
        print("\nExample queries:")
        print("1. is_critical_server eq true and has_exploit eq true")
        print("2. category eq 'SQL Injection'")
        print("3. search=vulnerability:'buffer overflow' and os:'Windows'")
        print("\nNote: For exact string matches, use single quotes, e.g., category eq 'SQL Injection'")
        print("Type 'exit' to quit")
        print("-" * 30)
        
        while True:
            try:
                # Get query from user
                query = input("\nEnter your query: ").strip()
                
                if query.lower() == 'exit':
                    break
                
                # Determine if it's a filter query or search query
                if query.lower().startswith('search='):
                    search_part = query[7:]  # Remove 'search=' prefix
                    filter_query = None
                else:
                    search_part = "*"
                    filter_query = query
                
                # Get fields to display
                fields = input("Enter fields to display (comma-separated, press enter for all): ").strip()
                select = fields if fields else None
                
                # Get number of results
                try:
                    top = int(input("Number of results to return (default 10): ") or "10")
                except ValueError:
                    top = 10
                
                # Execute search
                results = await client.search(
                    index_name=index_name,
                    search_query=search_part,
                    filter_query=filter_query,
                    select=select,
                    top=top
                )
                
                # Display results
                query_info = {
                    'filter': filter_query,
                    'search': search_part,
                    'fields': select or 'all',
                    'top': top
                }
                await display_results(results, query_info)
                
            except Exception as e:
                logger.error(f"Error executing query: {str(e)}")
                print(f"Error: {str(e)}")
                print("\nTips:")
                print("- For string comparisons, use single quotes: category eq 'SQL Injection'")
                print("- For boolean values, use 'true' or 'false' (lowercase)")
                print("- Check field names match exactly")
                print("- For date comparisons, use ISO format: 2024-02-14T00:00:00Z")

    except Exception as e:
        logger.error(f"Error initializing client: {str(e)}")
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
import azure.functions as func
import logging
import json
import os
import time
from typing import Dict, List, Optional, Union, Any
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError, ClientAuthenticationError

# Create the Function App instance
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

class IdentityMapper:
    """Class responsible for mapping identity information and related resources."""
    
    def __init__(self):
        # Get the subscription ID from environment variables
        self.subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
        
        if not self.subscription_id:
            logging.error("AZURE_SUBSCRIPTION_ID environment variable not set")
        else:
            logging.info(f"Using subscription ID: {self.subscription_id}")
            
        # Initialize clients as None
        self.resource_client = None
        self.msi_client = None
        
        # Initialize Azure clients with managed identity
        self._initialize_clients()
    
    def get_managed_identity_resources(self, identity_name: str, resource_group_name: str = None, 
                                    include_details: bool = False) -> List[Dict[str, Any]]:
        """
        Get resources that use a specific user-assigned managed identity.
        
        Args:
            identity_name (str): The name of the user-assigned managed identity
            resource_group_name (str, optional): The resource group containing the identity.
                                                If not specified, will search across all resource groups.
            include_details (bool): Whether to include detailed resource information
            
        Returns:
            List[Dict[str, Any]]: List of resources using the managed identity
        """
        logging.info(f"Getting resources for identity: {identity_name}, resource group: {resource_group_name or 'all'}, include details: {include_details}")
        
        if not identity_name:
            logging.error("Identity name is required")
            return []
        
        if not self.resource_client or not self.msi_client:
            logging.error("Azure clients not initialized")
            return []
        
        resources = []
        try:
            # Get the identity details first
            identity = None
            if resource_group_name:
                # If resource group is specified, look only in that group
                try:
                    logging.info(f"Looking for identity {identity_name} in resource group {resource_group_name}")
                    identity = self.msi_client.user_assigned_identities.get(
                        resource_group_name=resource_group_name,
                        resource_name=identity_name
                    )
                    logging.info(f"Found identity {identity_name} in resource group {resource_group_name}")
                except Exception as e:
                    logging.warning(f"Error getting user-assigned identity details in specified resource group: {str(e)}")
            else:
                # If no resource group specified, search across all resource groups
                logging.info(f"No resource group specified, searching for identity {identity_name} across all resource groups")
                all_identities = list(self.msi_client.user_assigned_identities.list_by_subscription())
                logging.info(f"Found {len(all_identities)} user-assigned identities in subscription")
                
                for i in all_identities:
                    logging.debug(f"Checking identity: {i.name} (comparing with {identity_name})")
                    if i.name.lower() == identity_name.lower():
                        identity = i
                        # Improved error handling for resource group extraction
                        try:
                            # Extract resource group name from the identity's ID
                            # The ID format should be: /subscriptions/{sub_id}/resourceGroups/{rg_name}/providers/...
                            parts = i.id.split('/')
                            resource_group_name = next((parts[idx+1] for idx, part in enumerate(parts) 
                                                      if part.lower() == 'resourcegroups' and idx+1 < len(parts)), 
                                                     "unknown")
                        except Exception as parse_error:
                            logging.warning(f"Error parsing resource group from ID '{i.id}': {str(parse_error)}")
                            resource_group_name = "unknown"
                        logging.info(f"Found identity {identity_name} in resource group {resource_group_name}")
                        break
            
            if not identity:
                logging.warning(f"Identity {identity_name} not found in any resource group")
                return []
            
            # Find resources that reference this identity
            identity_id = identity.id
            normalized_identity_id = identity_id.lower()  # Normalize for case-insensitive comparison
            logging.info(f"Searching for resources using identity with ID: {identity_id}")
            all_resources = list(self.resource_client.resources.list())
            logging.info(f"Found {len(all_resources)} total resources in subscription")
            
            resources_with_identity = 0
            resources_using_this_identity = 0
            
            for resource in all_resources:
                # Skip resources without identity information
                if not hasattr(resource, 'identity') or not resource.identity:
                    continue
                
                resources_with_identity += 1
                
                # Check if this resource references our user-assigned identity (case-insensitive)
                if (hasattr(resource.identity, 'user_assigned_identities') and 
                    resource.identity.user_assigned_identities):
                    
                    try:
                        # Log available identity IDs for debugging
                        identity_ids = list(resource.identity.user_assigned_identities.keys())
                        logging.debug(f"Resource {resource.name} has user assigned identities: {identity_ids}")
                        
                        # Case-insensitive matching for identity IDs
                        for resource_identity_id in identity_ids:
                            if resource_identity_id.lower() == normalized_identity_id:
                                resources_using_this_identity += 1
                                logging.info(f"Found resource {resource.name} (type: {resource.type}) using the specified identity")
                                
                                # Extract resource group in a safer way
                                try:
                                    parts = resource.id.split('/')
                                    res_group = next((parts[idx+1] for idx, part in enumerate(parts) 
                                                    if part.lower() == 'resourcegroups' and idx+1 < len(parts)), 
                                                   "unknown")
                                except Exception:
                                    res_group = "unknown"
                                
                                if include_details:
                                    resources.append({
                                        "id": resource.id,
                                        "name": resource.name,
                                        "resourceType": resource.type,
                                        "resourceGroup": res_group,
                                        "location": resource.location,
                                        "identity": {
                                            "type": resource.identity.type,
                                            "userAssignedIdentities": list(resource.identity.user_assigned_identities.keys())
                                        }
                                    })
                                else:
                                    resources.append({
                                        "id": resource.id,
                                        "name": resource.name,
                                        "resourceType": resource.type
                                    })
                                break  # Found a match, no need to check other identity IDs
                    except Exception as e:
                        logging.warning(f"Error checking resource {resource.name}: {str(e)}")
            
            logging.info(f"Checked {resources_with_identity} resources with identity information")
            logging.info(f"Found {resources_using_this_identity} resources using identity {identity_name}")
            
        except Exception as e:
            logging.error(f"Error getting resources using managed identity: {str(e)}")
        
        logging.info(f"Returning {len(resources)} resources using identity {identity_name}")
        return resources
    
    def find_resource_by_managed_identity_object_id(self, object_id: str) -> List[Dict[str, Any]]:
        """
        Find Azure resources associated with a managed identity by its Object ID.
        Enhanced to handle object IDs that might be:
        1. Principal ID of a User Assigned Identity
        2. Object ID of the User Assigned Identity resource itself
        3. Principal ID of a System Assigned Identity
        
        Args:
            object_id (str): The Object ID of the managed identity
                
        Returns:
            List[Dict[str, Any]]: List of resources associated with the managed identity
        """
        logging.info(f"Finding resources for managed identity with Object ID: {object_id}")
        
        if not object_id:
            logging.error("Object ID is required")
            return []
        
        if not self.resource_client or not self.msi_client:
            logging.error("Azure clients not initialized")
            return []
        
        resources = []
        try:
            # Approach 1: Check if object_id is a resource ID of a user-assigned identity
            if object_id.startswith('/subscriptions/'):
                try:
                    # Extract resource group and identity name from resource ID
                    parts = object_id.split('/')
                    if len(parts) >= 10 and parts[6].lower() == 'providers' and parts[7].lower() == 'microsoft.managedidentity':
                        resource_group_name = parts[4]
                        identity_name = parts[8]  # typically the 9th segment is 'userAssignedIdentities'
                        
                        logging.info(f"Object ID appears to be a resource ID. Extracting RG: {resource_group_name}, Identity: {identity_name}")
                        
                        # Get the identity details directly
                        try:
                            identity = self.msi_client.user_assigned_identities.get(
                                resource_group_name=resource_group_name,
                                resource_name=identity_name
                            )
                            
                            # Add the identity resource itself
                            resources.append({
                                "type": "UserAssignedIdentity",
                                "id": identity.id,
                                "name": identity.name,
                                "resourceGroup": resource_group_name,
                                "location": identity.location,
                                "principalId": identity.principal_id,
                                "clientId": identity.client_id,
                                "tenantId": identity.tenant_id
                            })
                            
                            # Find resources using this identity
                            identity_resources = self.get_managed_identity_resources(
                                identity_name=identity.name,
                                resource_group_name=resource_group_name,
                                include_details=True
                            )
                            
                            if identity_resources:
                                resources.append({
                                    "type": "ResourcesUsingIdentity",
                                    "identity": identity.name,
                                    "resources": identity_resources
                                })
                        except Exception as e:
                            logging.warning(f"Error retrieving identity using resource ID approach: {str(e)}")
                except Exception as e:
                    logging.warning(f"Error parsing object_id as resource ID: {str(e)}")
            
            # Approach 2: Find user-assigned identity where principal_id matches object_id
            try:
                logging.info("Searching for user-assigned identities by principal ID...")
                # List all user-assigned identities and filter by object ID
                user_identities = list(self.msi_client.user_assigned_identities.list_by_subscription())
                logging.info(f"Found {len(user_identities)} user-assigned identities in subscription")
                
                for identity in user_identities:
                    try:
                        # Extract resource group name from identity ID
                        id_parts = identity.id.split('/')
                        rg_index = -1
                        for i, part in enumerate(id_parts):
                            if part.lower() == 'resourcegroups':
                                rg_index = i
                                break
                        
                        resource_group_name = id_parts[rg_index + 1] if rg_index >= 0 and rg_index + 1 < len(id_parts) else "unknown"
                        logging.info(f"Checking identity: {identity.name} in resource group: {resource_group_name}")
                        
                        # Get detailed identity information including principal ID
                        identity_details = self.msi_client.user_assigned_identities.get(
                            resource_group_name=resource_group_name,
                            resource_name=identity.name
                        )
                        
                        # Check for matching principal ID
                        if hasattr(identity_details, 'principal_id'):
                            logging.info(f"Identity {identity.name} has principal ID: {identity_details.principal_id}")
                            if identity_details.principal_id == object_id:
                                # We found the user-assigned identity by principal ID
                                logging.info(f"Found matching user-assigned identity by principal ID: {identity.name}")
                                resources.append({
                                    "type": "UserAssignedIdentity",
                                    "id": identity.id,
                                    "name": identity.name,
                                    "resourceGroup": resource_group_name,
                                    "location": identity.location,
                                    "principalId": identity_details.principal_id,
                                    "clientId": identity_details.client_id,
                                    "tenantId": identity_details.tenant_id
                                })
                                
                                # Find resources using this identity
                                logging.info(f"Looking for resources using identity: {identity.name}")
                                identity_resources = self.get_managed_identity_resources(
                                    identity_name=identity.name,
                                    resource_group_name=resource_group_name,
                                    include_details=True
                                )
                                
                                if identity_resources:
                                    logging.info(f"Found {len(identity_resources)} resources using identity {identity.name}")
                                    resources.append({
                                        "type": "ResourcesUsingIdentity",
                                        "identity": identity.name,
                                        "resources": identity_resources
                                    })
                                else:
                                    logging.info(f"No resources found using identity {identity.name}")
                    except Exception as e:
                        logging.warning(f"Error checking identity {identity.name}: {str(e)}")
            except Exception as e:
                logging.warning(f"Error searching for user-assigned identities by principal ID: {str(e)}")
            
            # Approach 3: Check if object_id matches any identity's client_id
            if not resources:
                try:
                    logging.info("Searching for user-assigned identities by client ID...")
                    for identity in user_identities:
                        try:
                            # Extract resource group name from identity ID
                            id_parts = identity.id.split('/')
                            rg_index = -1
                            for i, part in enumerate(id_parts):
                                if part.lower() == 'resourcegroups':
                                    rg_index = i
                                    break
                            
                            resource_group_name = id_parts[rg_index + 1] if rg_index >= 0 and rg_index + 1 < len(id_parts) else "unknown"
                            
                            # Get detailed identity information
                            identity_details = self.msi_client.user_assigned_identities.get(
                                resource_group_name=resource_group_name,
                                resource_name=identity.name
                            )
                            
                            # Check for matching client ID
                            if hasattr(identity_details, 'client_id'):
                                if identity_details.client_id == object_id:
                                    # We found the user-assigned identity by client ID
                                    logging.info(f"Found matching user-assigned identity by client ID: {identity.name}")
                                    resources.append({
                                        "type": "UserAssignedIdentity",
                                        "id": identity.id,
                                        "name": identity.name,
                                        "resourceGroup": resource_group_name,
                                        "location": identity.location,
                                        "principalId": identity_details.principal_id,
                                        "clientId": identity_details.client_id,
                                        "tenantId": identity_details.tenant_id
                                    })
                                    
                                    # Find resources using this identity
                                    identity_resources = self.get_managed_identity_resources(
                                        identity_name=identity.name,
                                        resource_group_name=resource_group_name,
                                        include_details=True
                                    )
                                    
                                    if identity_resources:
                                        resources.append({
                                            "type": "ResourcesUsingIdentity",
                                            "identity": identity.name,
                                            "resources": identity_resources
                                        })
                        except Exception as e:
                            logging.warning(f"Error checking identity {identity.name} for client ID match: {str(e)}")
                except Exception as e:
                    logging.warning(f"Error searching for user-assigned identities by client ID: {str(e)}")
            
            # Approach 4: Search for system-assigned identities with this object ID
            try:
                logging.info("Searching for system-assigned identities...")
                all_resources = list(self.resource_client.resources.list())
                logging.info(f"Found {len(all_resources)} total resources in subscription")
                
                resources_with_identity = 0
                for resource in all_resources:
                    # Skip resources without identity information
                    if hasattr(resource, 'identity') and resource.identity:
                        resources_with_identity += 1
                        
                        # Check if this resource has a system-assigned identity with the matching object ID
                        if hasattr(resource.identity, 'principal_id'):
                            if resource.identity.principal_id == object_id:
                                logging.info(f"Found system-assigned identity on resource: {resource.name} (type: {resource.type})")
                                
                                # Extract resource group name from resource ID
                                res_group = "unknown"
                                try:
                                    parts = resource.id.split('/')
                                    for i, part in enumerate(parts):
                                        if part.lower() == 'resourcegroups' and i + 1 < len(parts):
                                            res_group = parts[i + 1]
                                            break
                                except Exception:
                                    pass
                                
                                resources.append({
                                    "type": "SystemAssignedIdentity",
                                    "id": resource.id,
                                    "name": resource.name,
                                    "resourceType": resource.type,
                                    "resourceGroup": res_group,
                                    "location": resource.location,
                                    "principalId": resource.identity.principal_id,
                                    "tenantId": resource.identity.tenant_id if hasattr(resource.identity, 'tenant_id') else None
                                })
                
                logging.info(f"Checked {resources_with_identity} resources with identity information")
            except Exception as e:
                logging.warning(f"Error searching for system-assigned identities: {str(e)}")
            
        except Exception as e:
            logging.error(f"Error finding resources by managed identity object ID: {str(e)}")
        
        logging.info(f"Found {len(resources)} total results for object ID {object_id}")
        return resources
        
   
    def _initialize_clients(self):
        """
        Initialize Azure clients with appropriate authentication.
        This method attempts managed identity first, then falls back to DefaultAzureCredential.
        """
        if not self.subscription_id:
            logging.error("Cannot initialize Azure clients: AZURE_SUBSCRIPTION_ID not set")
            return
            
        # Log authentication attempt
        logging.info("Initializing Azure clients with managed identity authentication")
        
        # First try with ManagedIdentityCredential
        try:
            # For Function Apps in Azure, managed identity is the recommended approach
            logging.info("Attempting authentication with ManagedIdentityCredential")
            credential = ManagedIdentityCredential()
            
            # Test the credential with a client
            logging.info("Creating ResourceManagementClient with managed identity")
            self.resource_client = ResourceManagementClient(
                credential=credential,
                subscription_id=self.subscription_id
            )
            
            # Try a simple operation to validate the credential
            logging.info("Testing managed identity by listing resource groups")
            try:
                rg_list = list(self.resource_client.resource_groups.list())
                logging.info(f"Successfully listed {len(rg_list)} resource groups using managed identity")
            except Exception as perm_error:
                logging.error(f"PERMISSION ERROR: The function app's managed identity doesn't have sufficient permissions to list resource groups. Error: {str(perm_error)}")
                logging.error("Please assign at least 'Reader' role at the subscription level to the function app's managed identity")
                self.resource_client = None
                raise
            
            # If we got here, the managed identity worked
            logging.info("Successfully authenticated using managed identity")
            
            # Initialize the MSI client
            logging.info("Creating ManagedServiceIdentityClient with managed identity")
            self.msi_client = ManagedServiceIdentityClient(
                credential=credential,
                subscription_id=self.subscription_id
            )
            
            # Test MSI client permissions
            try:
                user_identities = list(self.msi_client.user_assigned_identities.list_by_subscription())
                logging.info(f"Successfully listed user-assigned identities using managed identity")
            except Exception as msi_perm_error:
                logging.error(f"PERMISSION ERROR: The function app's managed identity doesn't have sufficient permissions to list managed identities. Error: {str(msi_perm_error)}")
                logging.error("Please assign 'Managed Identity Operator' role to the function app's managed identity")
                # Don't raise here, as we at least have resource_client working
            
        except (ClientAuthenticationError, Exception) as e:
            if "unauthorized" in str(e).lower() or "permission" in str(e).lower() or "access denied" in str(e).lower():
                logging.error(f"PERMISSION ERROR: The function app doesn't have a managed identity or it lacks necessary permissions. Error: {str(e)}")
                logging.error("Please enable a system-assigned managed identity for this function app and grant it 'Reader' and 'Managed Identity Operator' roles")
            else:
                logging.warning(f"Managed identity authentication failed: {str(e)}")
            
            logging.info("Trying alternative authentication methods with DefaultAzureCredential")
            
            try:
                # Fall back to DefaultAzureCredential which tries multiple authentication methods
                logging.info("Attempting authentication with DefaultAzureCredential")
                credential = DefaultAzureCredential()
                
                logging.info("Creating ResourceManagementClient with DefaultAzureCredential")
                self.resource_client = ResourceManagementClient(
                    credential=credential,
                    subscription_id=self.subscription_id
                )
                
                # Test the credential with permission check
                logging.info("Testing DefaultAzureCredential by listing resource groups")
                try:
                    rg_list = list(self.resource_client.resource_groups.list())
                    logging.info(f"Successfully listed {len(rg_list)} resource groups using DefaultAzureCredential")
                except Exception as default_perm_error:
                    logging.error(f"PERMISSION ERROR: The DefaultAzureCredential doesn't have sufficient permissions. Error: {str(default_perm_error)}")
                    logging.error("Please ensure your credentials have at least 'Reader' role at the subscription level")
                    self.resource_client = None
                    raise
                
                # If we got here, DefaultAzureCredential worked
                logging.info("Successfully authenticated using DefaultAzureCredential")
                
                # Initialize the MSI client
                logging.info("Creating ManagedServiceIdentityClient with DefaultAzureCredential")
                self.msi_client = ManagedServiceIdentityClient(
                    credential=credential,
                    subscription_id=self.subscription_id
                )
                
            except Exception as e2:
                if "unauthorized" in str(e2).lower() or "permission" in str(e2).lower() or "access denied" in str(e2).lower():
                    logging.error(f"PERMISSION ERROR: All authentication methods failed due to insufficient permissions. Error: {str(e2)}")
                    logging.error("Required permissions: 'Reader' role at subscription level.")
                else:
                    logging.error(f"All authentication methods failed. Last error: {str(e2)}")
                
                self.resource_client = None
                self.msi_client = None


# Main function that Logic Apps will call
@app.route(route="", methods=["POST"])
def managed_identity_mapper(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function that maps identity information and related resources.
    Compatible with Logic Apps.
    
    Args:
        req (func.HttpRequest): The HTTP request object
        
    Returns:
        func.HttpResponse: The HTTP response object
    """
    # Log the start of function execution with time for tracking duration
    start_time = time.time()
    request_id = req.headers.get('x-ms-client-request-id', 'unknown')
    logging.info(f"Function started with request ID: {request_id}")
    
    # Log request details
    logging.info(f"Request method: {req.method}")
    logging.info(f"Request URL: {req.url}")
    logging.info(f"Request headers: {dict(req.headers)}")
    
    try:
        # Parse the request body as JSON
        req_body = req.get_json()
        logging.info(f"Request body: {json.dumps(req_body)}")
    except ValueError:
        # If no JSON body or invalid JSON, initialize empty dict
        logging.warning("Request did not contain valid JSON body")
        req_body = {}
    
    # Initialize the identity mapper
    mapper = IdentityMapper()
    
    # Get parameters from request body or query params
    object_id = req.params.get('ObjectId')
    if not object_id and req_body and 'ObjectId' in req_body:
        object_id = req_body.get('ObjectId')
    
    if object_id:
        logging.info(f"Object ID: {object_id}")
    
    identity_name = req.params.get('IdentityName')
    if not identity_name and req_body and 'IdentityName' in req_body:
        identity_name = req_body.get('IdentityName')
    
    if identity_name:
        logging.info(f"Identity name: {identity_name}")
    
    resource_group_name = req.params.get('resourceGroupName')
    if not resource_group_name and req_body and 'resourceGroupName' in req_body:
        resource_group_name = req_body.get('resourceGroupName')
    
    if resource_group_name:
        logging.info(f"Resource group name: {resource_group_name}")
    
    include_details_str = req.params.get('includeDetails',True)
    include_details = include_details_str == "true" if include_details_str else False
    if not include_details_str and req_body and 'includeDetails' in req_body:
        include_details = req_body.get('includeDetails') is True
    
    logging.info(f"Include details: {include_details}")
    
    # Determine operation based on parameters provided
    result = None
    if object_id:
        logging.info(f"ObjectId parameter found, searching by object ID: {object_id}")
        result = mapper.find_resource_by_managed_identity_object_id(object_id)
    elif identity_name:
        logging.info(f"IdentityName parameter found, searching resources for identity: {identity_name}")
        result = mapper.get_managed_identity_resources(
            identity_name=identity_name,
            resource_group_name=resource_group_name,
            include_details=include_details
        )
    else:
        logging.error("No valid search parameters provided")
        return func.HttpResponse(
            body=json.dumps({
                "error": "Missing required parameters",
                "requiredParameters": "Either 'ObjectId' or 'IdentityName' must be provided"
            }),
            mimetype="application/json",
            status_code=400
        )
    
    # Log the result
    result_type = type(result).__name__
    if isinstance(result, list):
        result_size = len(result)
        logging.info(f"Operation successful. Result is a list with {result_size} items.")
        
        # Wrap the list result in a structured response with count
        response_body = {
            "status": "success",
            "count": result_size,
            "resources": result
        }
    elif isinstance(result, dict):
        result_keys = list(result.keys())
        logging.info(f"Operation successful. Result is a dictionary with keys: {result_keys}")
        
        response_body = {
            "status": "success",
            "count": len(result.keys()),
            "data": result
        }
    else:
        logging.info(f"Operation successful. Result type: {result_type}")
        response_body = {
            "status": "success",
            "count": 0 if result is None else 1,
            "data": result
        }

    # Return the result with the added metadata
    response = func.HttpResponse(
        body=json.dumps(response_body, default=lambda o: o.__dict__ if hasattr(o, '__dict__') else str(o)),
        mimetype="application/json",
        status_code=200
    )
    
    # Log execution duration
    end_time = time.time()
    execution_time = end_time - start_time
    logging.info(f"Function completed in {execution_time:.2f} seconds with request ID: {request_id}")
    
    return response
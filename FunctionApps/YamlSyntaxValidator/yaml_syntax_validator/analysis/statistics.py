"""Statistical analysis module for YAML content."""

from typing import Dict, List, Any

def get_structure_info(data: Any, prefix: str = '') -> List[str]:
    """
    Analyze and return information about the YAML structure.
    
    Args:
        data: The parsed YAML data
        prefix: String prefix for nested structures
        
    Returns:
        List of strings describing the structure
    """
    structure_info = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                structure_info.append(f"{prefix}{key}: {type(value).__name__}")
                structure_info.extend(get_structure_info(value, prefix + '  '))
            else:
                structure_info.append(f"{prefix}{key}: {type(value).__name__}")
    elif isinstance(data, list):
        for i, item in enumerate(data):
            structure_info.append(f"{prefix}- item{i+1}: {type(item).__name__}")
            if isinstance(item, (dict, list)):
                structure_info.extend(get_structure_info(item, prefix + '  '))
    return structure_info

def get_yaml_statistics(yaml_content: str) -> Dict[str, int]:
    """
    Generate statistics about the YAML content.
    
    Args:
        yaml_content: Raw YAML content string
        
    Returns:
        Dictionary containing various statistics
    """
    lines = yaml_content.split('\n')
    return {
        "total_lines": len(lines),
        "empty_lines": len([l for l in lines if not l.strip()]),
        "mapping_entries": len([l for l in lines if ':' in l]),
        "sequence_items": len([l for l in lines if l.strip().startswith('-')]),
    }

def get_best_practices(yaml_content: str) -> List[str]:
    """
    Analyze YAML content and suggest best practices.
    
    Args:
        yaml_content: Raw YAML content string
        
    Returns:
        List of suggestions for following YAML best practices
    """
    suggestions = []
    lines = yaml_content.split('\n')
    
    if any('\t' in line for line in lines):
        suggestions.append("Use spaces instead of tabs for indentation")
    
    if any(line.startswith('- ') and ':' in line and '"' not in line and "'" not in line 
           for line in lines):
        suggestions.append("Consider quoting values containing special characters")
    
    if any(line.strip().endswith(':') for line in lines):
        suggestions.append("Add a space after colons in mappings")
    
    return suggestions
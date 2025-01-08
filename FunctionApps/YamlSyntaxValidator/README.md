# YAML Syntax Validator

A Python Azure Function that validates YAML syntax with a focus on Security Copilot plugin manifests. This service provides detailed, human-readable error messages and suggestions for fixing YAML syntax issues.

## Features

- Comprehensive YAML syntax validation
- Security checks for file size and structure
- Detailed error reporting with line numbers and context
- Multiple error detection in a single pass
- Best practice suggestions
- Statistical analysis of YAML structure

## API Endpoint

The function exposes a single HTTP POST endpoint that accepts YAML content and returns validation results.

### Request
- Method: POST
- Content-Type: text/plain
- Body: Raw YAML content

### Response
```typescript
{
  isValid: boolean;
  error_details?: {
    errors: Array<{
      line: number;
      column: number;
      message: string;
      error_type: string;
      context?: string[];
      code_context?: {
        lines: string[];
        start_line: number;
        problematic_line: number;
        problematic_column: number;
      };
    }>;
    total_errors: number;
  };
  details?: {
    structure: string[];
    statistics: {
      total_lines: number;
      empty_lines: number;
      mapping_entries: number;
      sequence_items: number;
    };
  };
}
```

## Security Features

- Maximum file size enforcement (1MB)
- Maximum nesting depth checks (20 levels)
- Sequence item limits (1000 items)
- Restricted YAML tag usage
- Memory usage monitoring

## Project Structure

```
.
├── config.py               # Configuration constants
├── errors/
│   └── error_handler.py    # Error processing and formatting
├── parsers/
│   └── yaml_parser.py      # YAML parsing and validation
├── security/
│   └── validator.py        # Security validation
├── analysis/
│   └── statistics.py       # YAML structure analysis
└── __init__.py            # Main function handler
```

## Development Setup

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Install Azure Functions Core Tools
4. Run locally:
   ```bash
   func start
   ```

## Deployment

The function is deployed to Azure Functions. Deployment occurs through Azure DevOps pipelines or GitHub Actions.

## Configuration

Adjustable parameters in `config.py`:
- `MAX_YAML_SIZE`: Maximum file size (default 1MB)
- `MAX_NESTING_DEPTH`: Maximum nesting level (default 20)
- `MAX_SEQUENCE_ITEMS`: Maximum sequence items (default 1000)
- `ALLOWED_TAGS`: List of allowed YAML tags

## Error Messages

The service provides detailed error messages with:
- Line and column numbers
- Context around the error
- Human-readable explanations
- Suggestions for fixes
- Code examples where applicable

## Related Projects

This function is used by the YAML Validator UI (private repository) which provides a web interface for the validation service.

## Contributing

Contributions are welcome! Please submit pull requests with:
- Clear description of changes
- Updated tests if applicable
- Documentation updates if needed

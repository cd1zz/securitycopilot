import os
import sys
from typing import Tuple, List
import codecs

def check_bom(file_path: str) -> str:
    """Check for presence of BOM in the file."""
    boms = {
        codecs.BOM_UTF8: "UTF-8-BOM",
        codecs.BOM_UTF16_LE: "UTF-16-LE",
        codecs.BOM_UTF16_BE: "UTF-16-BE",
        codecs.BOM_UTF32_LE: "UTF-32-LE",
        codecs.BOM_UTF32_BE: "UTF-32-BE",
    }
    
    with open(file_path, 'rb') as f:
        raw = f.read(4)  # Read first 4 bytes
        for bom, encoding in boms.items():
            if raw.startswith(bom):
                return encoding
    return "No BOM detected"

def analyze_line_endings(file_path: str) -> Tuple[int, int, int]:
    """Count different types of line endings in the file."""
    with open(file_path, 'rb') as f:
        content = f.read()
        crlf_count = content.count(b'\r\n')
        lf_count = content.count(b'\n') - crlf_count  # Subtract CRLF counts to get pure LF
        cr_count = content.count(b'\r') - crlf_count  # Subtract CRLF counts to get pure CR
    return crlf_count, lf_count, cr_count

def check_file_permissions(file_path: str) -> dict:
    """Check file permissions and locking status."""
    result = {
        "readable": os.access(file_path, os.R_OK),
        "writable": os.access(file_path, os.W_OK),
        "executable": os.access(file_path, os.X_OK),
    }
    
    # Try to open for writing to check if file is locked
    try:
        with open(file_path, 'r+'):
            result["locked"] = False
    except IOError:
        result["locked"] = True
    except Exception as e:
        result["locked"] = f"Unknown: {str(e)}"
    
    return result

def analyze_file_content(file_path: str, problem_position: int, context_size: int = 50) -> Tuple[List[Tuple[int, int, bytes]], str, str]:
    """Analyze file content with enhanced diagnostics."""
    with open(file_path, 'rb') as f:
        content = f.read()
        
        # Get context around problem position
        start = max(0, problem_position - context_size)
        end = min(len(content), problem_position + context_size)
        
        # Show raw bytes around error position
        context_before = content[start:problem_position]
        context_after = content[problem_position:end]
        
        # Find any unusual bytes
        problematic_chars = []
        for i, byte_val in enumerate(content):
            # Look for control characters (except common ones like newline, tab)
            if byte_val < 32 and byte_val not in {9, 10, 13}:  # 9=TAB, 10=LF, 13=CR
                problematic_chars.append((i, byte_val, f"CTRL-{byte_val}"))
                
    return problematic_chars, context_before, context_after

def diagnose_csv_file(file_path: str, error_position: int):
    """Enhanced CSV file diagnostics."""
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return

    print(f"\nEnhanced File Analysis for: {file_path}")
    print(f"File size: {os.path.getsize(file_path):,} bytes")
    
    # Check BOM
    bom_result = check_bom(file_path)
    print(f"\nBOM Check: {bom_result}")
    
    # Analyze line endings
    crlf, lf, cr = analyze_line_endings(file_path)
    print(f"\nLine Endings Analysis:")
    print(f"CRLF (Windows): {crlf}")
    print(f"LF (Unix): {lf}")
    print(f"CR (Legacy Mac): {cr}")
    
    # Check file permissions
    perms = check_file_permissions(file_path)
    print(f"\nFile Permissions:")
    for k, v in perms.items():
        print(f"{k}: {v}")
    
    # Analyze content
    problematic_chars, context_before, context_after = analyze_file_content(file_path, error_position)
    
    print(f"\nContext around error position {error_position}:")
    print("Raw bytes before error:")
    print(context_before.hex(' '))
    print("↑ Error occurs here")
    print("Raw bytes after error:")
    print(context_after.hex(' '))
    
    if problematic_chars:
        print("\nProblematic characters found:")
        for pos, byte_val, char_type in problematic_chars:
            print(f"Position {pos}: {char_type} (0x{byte_val:02x})")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python csv_diagnostic.py <csv_file>")
        sys.exit(1)
        
    diagnose_csv_file(sys.argv[1], 1976)
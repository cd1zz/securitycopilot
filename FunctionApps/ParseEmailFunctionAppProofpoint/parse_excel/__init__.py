import base64
import logging
import zipfile
from xml.etree import ElementTree as ET
from io import BytesIO
import re

logger = logging.getLogger(__name__)

def extract_and_clean_excel_text(excel_base64):
    """
    Extracts text and metadata from an Excel bytes object and performs basic cleanup.
    :param excel_base64: Excel file content as base64 string
    :return: Extracted text and metadata from the Excel file
    """
    if not excel_base64:
        raise ValueError("Input excel_base64 cannot be empty")

    excel_decoded = base64.b64decode(excel_base64)
    excel_bytes = BytesIO(excel_decoded)

    # Initialize results dictionary
    results = {
        'text_content': '',  # Changed to string instead of list
        'urls': [],
        'hyperlinks': [],
        'vba_code': {},
        'formulas': [],
        'comments': [],
        'embedded_files': []
    }

    extracted_text = []  # Temporary list for collecting text

    try:
        logging.info("Extracting content from Excel.")
        
        with zipfile.ZipFile(excel_bytes, 'r') as z:
            # Process VBA code if present
            if 'xl/vbaProject.bin' in z.namelist():
                try:
                    vba_binary = z.read('xl/vbaProject.bin')
                    # Look for VBA code segments
                    modules = re.findall(b'Attribute VB_Name = "([^"]+)".*?(?=Attribute VB_Name|$)', 
                                       vba_binary, re.DOTALL)
                    
                    for i, module in enumerate(modules):
                        try:
                            decoded_content = module.decode('utf-8', errors='ignore')
                            cleaned_content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', decoded_content)
                            if cleaned_content.strip():  # Only add if there's content
                                results['vba_code'][f'Module_{i}'] = cleaned_content
                        except Exception as e:
                            logger.warning(f"Could not decode VBA module {i}: {str(e)}")
                except Exception as e:
                    logger.warning(f"Error processing VBA project: {str(e)}")

            # Process relationship files for hyperlinks
            for filename in z.namelist():
                if filename.endswith('.rels'):
                    try:
                        content = z.read(filename).decode('utf-8', errors='ignore')
                        root = ET.fromstring(content)
                        for relationship in root.findall('.//{http://schemas.openxmlformats.org/package/2006/relationships}Relationship'):
                            rel_type = relationship.get('Type', '')
                            target = relationship.get('Target', '')
                            
                            if 'hyperlink' in rel_type.lower() and target:  # Only add if target exists
                                results['hyperlinks'].append({
                                    'file': filename,
                                    'target': target,
                                    'type': 'hyperlink'
                                })
                    except ET.ParseError as e:
                        logger.warning(f"Could not parse relationships in {filename}: {str(e)}")
                    except Exception as e:
                        logger.warning(f"Error processing relationships in {filename}: {str(e)}")

            # Process XML files for content
            for filename in z.namelist():
                if filename.endswith('.xml'):
                    try:
                        content = z.read(filename).decode('utf-8', errors='ignore')
                        root = ET.fromstring(content)
                        
                        # Extract text content
                        for elem in root.iter():
                            if elem.text and elem.text.strip():
                                extracted_text.append(elem.text.strip())
                        
                        # Extract URLs
                        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', content)
                        for url in urls:
                            if url and not any(domain in url.lower() for domain in [
                                'microsoft.com', 'live.com', 'office.com', 'purl.org',
                                'microsoftonline.com', 'openxmlformats.org', 'w3.org'
                            ]):
                                results['urls'].append({
                                    'file': filename,
                                    'url': url
                                })
                        
                        # Extract formulas
                        for formula in root.findall('.//*[@f]'):
                            formula_text = formula.get('f')
                            if formula_text:  # Only add if formula exists
                                results['formulas'].append({
                                    'file': filename,
                                    'formula': formula_text
                                })
                        
                        # Extract comments
                        namespaces = {'mc': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                        comments = (root.findall('.//comment') + 
                                  root.findall('.//mc:comment', namespaces))
                        for comment in comments:
                            if comment.text and comment.text.strip():
                                results['comments'].append(comment.text.strip())
                                
                    except ET.ParseError as e:
                        logger.warning(f"Could not parse XML in {filename}: {str(e)}")
                    except Exception as e:
                        logger.warning(f"Error processing XML in {filename}: {str(e)}")

            # Check for embedded files
            for filename in z.namelist():
                if 'embeddings' in filename.lower():
                    try:
                        results['embedded_files'].append({
                            'file': filename,
                            'size': z.getinfo(filename).file_size
                        })
                    except Exception as e:
                        logger.warning(f"Error processing embedded file {filename}: {str(e)}")

        # Clean and join the extracted text
        if extracted_text:  # Only process if we have text
            full_text = ' '.join(extracted_text)
            cleaned_text = re.sub(r'[^\x20-\x7E\n\r]+', '', full_text)
            cleaned_text = re.sub(r'\s+', ' ', cleaned_text).strip()
            results['text_content'] = cleaned_text

    except Exception as e:
        logging.error(f"Failed to extract text from Excel: {str(e)}")
        raise

    return results
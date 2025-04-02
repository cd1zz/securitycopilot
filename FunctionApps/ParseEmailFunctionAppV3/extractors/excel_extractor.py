# extractors/excel_extractor.py
import io
import logging
import traceback
import zipfile
import re
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

def extract_text_from_excel(excel_data):
    """
    Extract text content from Excel binary data.
    
    Args:
        excel_data (bytes): The binary content of the Excel file
        
    Returns:
        str: Extracted text from the Excel file
    """
    try:
        # Create a file-like object from the binary data
        excel_file = io.BytesIO(excel_data)
        
        # Try pandas first for simple structured data extraction
        try:
            import pandas as pd
            
            # Try reading with pandas - handles xls and xlsx
            dfs = pd.read_excel(excel_file, sheet_name=None)
            
            # Concatenate all sheets into a text representation
            text_content = []
            for sheet_name, df in dfs.items():
                text_content.append(f"Sheet: {sheet_name}")
                text_content.append(df.to_string(index=False))
                text_content.append("\n")
            
            result = "\n".join(text_content).strip()
            logger.debug(f"Successfully extracted Excel text using pandas, {len(result)} characters")
            return result
            
        except Exception as pandas_err:
            logger.warning(f"Pandas Excel reading failed: {str(pandas_err)}, trying deep extraction")
            
            # Reset file position
            excel_file.seek(0)
            
            # Try deep extraction for XLSX files
            try:
                # Deep extraction similar to your original code
                return extract_excel_deep(excel_data)
            except Exception as deep_err:
                logger.warning(f"Deep Excel extraction failed: {str(deep_err)}, trying openpyxl")
                
                # Reset file position
                excel_file.seek(0)
                
                # Try using openpyxl as a fallback
                try:
                    import openpyxl
                    
                    workbook = openpyxl.load_workbook(excel_file, data_only=True)
                    text_content = []
                    
                    for sheet in workbook.worksheets:
                        text_content.append(f"Sheet: {sheet.title}")
                        
                        for row in sheet.iter_rows():
                            row_values = [str(cell.value) if cell.value is not None else "" for cell in row]
                            text_content.append("\t".join(row_values))
                        
                        text_content.append("\n")
                    
                    result = "\n".join(text_content).strip()
                    logger.debug(f"Successfully extracted Excel text using openpyxl, {len(result)} characters")
                    return result
                    
                except Exception as openpyxl_err:
                    logger.warning(f"Openpyxl Excel reading failed: {str(openpyxl_err)}, trying xlrd")
                    
                    # Reset file position
                    excel_file.seek(0)
                    
                    # Try xlrd as a last resort for xls files
                    try:
                        import xlrd
                        
                        workbook = xlrd.open_workbook(file_contents=excel_data)
                        text_content = []
                        
                        for sheet_idx in range(workbook.nsheets):
                            sheet = workbook.sheet_by_index(sheet_idx)
                            text_content.append(f"Sheet: {sheet.name}")
                            
                            for row_idx in range(sheet.nrows):
                                row_values = [str(cell.value) for cell in sheet.row(row_idx)]
                                text_content.append("\t".join(row_values))
                            
                            text_content.append("\n")
                        
                        result = "\n".join(text_content).strip()
                        logger.debug(f"Successfully extracted Excel text using xlrd, {len(result)} characters")
                        return result
                        
                    except Exception as xlrd_err:
                        logger.error(f"All Excel reading methods failed: {str(xlrd_err)}")
                        return f"[Error: Could not extract Excel text with any available method]"
    
    except Exception as e:
        logger.error(f"Error extracting text from Excel: {str(e)}")
        logger.debug(traceback.format_exc())
        return f"[Error extracting Excel text: {str(e)}]"

def extract_excel_deep(excel_data):
    """
    Extract detailed information from Excel files including text, URLs, VBA code, etc.
    
    Args:
        excel_data (bytes): The binary content of the Excel file
        
    Returns:
        str: Extracted text content and metadata
    """
    excel_bytes = io.BytesIO(excel_data)
    extracted_text = []
    metadata = []

    try:
        logger.info("Performing deep extraction from Excel file")
        
        with zipfile.ZipFile(excel_bytes, 'r') as z:
            # Process VBA code if present
            if 'xl/vbaProject.bin' in z.namelist():
                try:
                    vba_binary = z.read('xl/vbaProject.bin')
                    # Look for VBA code segments
                    modules = re.findall(b'Attribute VB_Name = "([^"]+)".*?(?=Attribute VB_Name|$)', 
                                       vba_binary, re.DOTALL)
                    
                    if modules:
                        metadata.append("# Excel VBA Code")
                    
                    for i, module in enumerate(modules):
                        try:
                            decoded_content = module.decode('utf-8', errors='ignore')
                            cleaned_content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', decoded_content)
                            if cleaned_content.strip():  # Only add if there's content
                                metadata.append(f"# Module {i}")
                                metadata.append(cleaned_content)
                        except Exception as e:
                            logger.warning(f"Could not decode VBA module {i}: {str(e)}")
                except Exception as e:
                    logger.warning(f"Error processing VBA project: {str(e)}")

            # Process relationship files for hyperlinks
            hyperlinks = []
            for filename in z.namelist():
                if filename.endswith('.rels'):
                    try:
                        content = z.read(filename).decode('utf-8', errors='ignore')
                        root = ET.fromstring(content)
                        for relationship in root.findall('.//{http://schemas.openxmlformats.org/package/2006/relationships}Relationship'):
                            rel_type = relationship.get('Type', '')
                            target = relationship.get('Target', '')
                            
                            if 'hyperlink' in rel_type.lower() and target:  # Only add if target exists
                                hyperlinks.append(target)
                    except ET.ParseError as e:
                        logger.warning(f"Could not parse relationships in {filename}: {str(e)}")
                    except Exception as e:
                        logger.warning(f"Error processing relationships in {filename}: {str(e)}")
            
            if hyperlinks:
                metadata.append("# Hyperlinks")
                metadata.append("\n".join(hyperlinks))
            
            # Process XML files for content
            urls = set()
            formulas = []
            comments = []
            
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
                        found_urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', content)
                        for url in found_urls:
                            if url and not any(domain in url.lower() for domain in [
                                'microsoft.com', 'live.com', 'office.com', 'purl.org',
                                'microsoftonline.com', 'openxmlformats.org', 'w3.org'
                            ]):
                                urls.add(url)
                        
                        # Extract formulas
                        for formula in root.findall('.//*[@f]'):
                            formula_text = formula.get('f')
                            if formula_text:  # Only add if formula exists
                                formulas.append(formula_text)
                        
                        # Extract comments
                        namespaces = {'mc': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                        found_comments = (root.findall('.//comment') + 
                                        root.findall('.//mc:comment', namespaces))
                        for comment in found_comments:
                            if comment.text and comment.text.strip():
                                comments.append(comment.text.strip())
                                
                    except ET.ParseError as e:
                        logger.warning(f"Could not parse XML in {filename}: {str(e)}")
                    except Exception as e:
                        logger.warning(f"Error processing XML in {filename}: {str(e)}")

            # Add URLs, formulas, and comments to metadata
            if urls:
                metadata.append("# URLs")
                metadata.append("\n".join(urls))
            
            if formulas:
                metadata.append("# Formulas")
                metadata.append("\n".join(formulas))
            
            if comments:
                metadata.append("# Comments")
                metadata.append("\n".join(comments))

            # Check for embedded files
            embedded_files = []
            for filename in z.namelist():
                if 'embeddings' in filename.lower():
                    try:
                        embedded_files.append(f"{filename} ({z.getinfo(filename).file_size} bytes)")
                    except Exception as e:
                        logger.warning(f"Error processing embedded file {filename}: {str(e)}")
            
            if embedded_files:
                metadata.append("# Embedded Files")
                metadata.append("\n".join(embedded_files))

        # Clean and join the extracted text
        if extracted_text:  # Only process if we have text
            full_text = ' '.join(extracted_text)
            cleaned_text = re.sub(r'[^\x20-\x7E\n\r]+', '', full_text)
            cleaned_text = re.sub(r'\s+', ' ', cleaned_text).strip()
            
            # Combine main text and metadata
            result = cleaned_text
            if metadata:
                result += "\n\n" + "\n\n".join(metadata)
            
            return result
        elif metadata:
            # Return just metadata if no text content
            return "\n\n".join(metadata)
        else:
            return "[No text content found in Excel file]"

    except zipfile.BadZipFile:
        logger.warning("Not a valid XLSX file (bad zip format), passing to other extractors")
        raise
    except Exception as e:
        logger.error(f"Failed to extract text from Excel (deep extraction): {str(e)}")
        logger.debug(traceback.format_exc())
        raise
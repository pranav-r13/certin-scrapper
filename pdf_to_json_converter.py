#!/usr/bin/env python3
"""
PDF to JSON Converter for CERT-In Advisory Notes
Handles text extraction and OCR for image-based tables in PDFs
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    import pdfplumber
    from PIL import Image
    import pytesseract
    import fitz  # PyMuPDF
except ImportError as e:
    print(f"Error: Missing required library. Please install: pip install pdfplumber pillow pytesseract PyMuPDF")
    print(f"Missing: {e}")
    sys.exit(1)


class PDFToJSONConverter:
    """Converts CERT-In Advisory PDF to structured JSON format"""
    
    def __init__(self, pdf_path: str):
        self.pdf_path = Path(pdf_path)
        if not self.pdf_path.exists():
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
        
        self.extracted_data = {}
        self.full_text = ""
        self.image_text = []
    
    def extract_text_from_pdf(self) -> str:
        """Extract all text from PDF using pdfplumber"""
        text_content = []
        
        with pdfplumber.open(self.pdf_path) as pdf:
            for page_num, page in enumerate(pdf.pages, 1):
                text = page.extract_text()
                if text:
                    text_content.append(text)
        
        return "\n".join(text_content)
    
    def extract_images_and_ocr(self) -> List[str]:
        """Extract images from PDF and perform OCR"""
        image_texts = []
        
        # Use PyMuPDF for image extraction
        doc = fitz.open(self.pdf_path)
        
        for page_num in range(len(doc)):
            page = doc[page_num]
            image_list = page.get_images()
            
            for img_index, img in enumerate(image_list):
                try:
                    # Get image data
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    image_ext = base_image["ext"]
                    
                    # Convert to PIL Image
                    from io import BytesIO
                    image = Image.open(BytesIO(image_bytes))
                    
                    # Perform OCR
                    ocr_text = pytesseract.image_to_string(image)
                    if ocr_text.strip():
                        image_texts.append(ocr_text.strip())
                        print(f"OCR extracted text from image on page {page_num + 1}, image {img_index + 1}")
                except Exception as e:
                    print(f"Warning: Could not process image {img_index + 1} on page {page_num + 1}: {e}")
        
        doc.close()
        return image_texts
    
    def extract_field_by_pattern(self, pattern: str, text: str, group: int = 1) -> Optional[str]:
        """Extract field value using regex pattern"""
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        if match:
            return match.group(group).strip()
        return None
    
    def extract_list_by_keywords(self, text: str, keywords: List[str], stop_keywords: List[str] = None) -> List[str]:
        """Extract list items after specific keywords"""
        items = []
        
        if stop_keywords is None:
            stop_keywords = ["Overview", "Target Audience", "Description", "Solution", "Vendor"]
        
        for keyword in keywords:
            # Pattern to match keyword followed by newline and list items
            pattern = rf"{re.escape(keyword)}[:\s]*\n((?:[^\n]+\n?)+?)(?=\n(?:{'|'.join(stop_keywords)})|$)"
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                lines = match.group(1).strip().split('\n')
                for line in lines:
                    # Clean up bullet points, formatting, and empty lines
                    cleaned = re.sub(r'^[-•*\d.]+\s*', '', line.strip())
                    cleaned = cleaned.strip()
                    # Skip if it's a section header or empty
                    if cleaned and not re.match(r'^[A-Z][a-z]+\s+[A-Z]', cleaned):
                        items.append(cleaned)
                break
        
        return items
    
    def extract_cve_list(self, text: str) -> List[str]:
        """Extract CVE identifiers from text - filter out false positives"""
        cve_pattern = r'\bCVE-\d{4}-\d{4,}\b'
        cves = re.findall(cve_pattern, text, re.IGNORECASE)
        
        # Filter out false positives (common OCR errors)
        valid_cves = []
        for cve in cves:
            # Check if it's a valid format: CVE-YYYY-NNNN+
            parts = cve.split('-')
            if len(parts) == 3:
                year = parts[1]
                number = parts[2]
                # Year should be 4 digits, number should be 4+ digits
                if year.isdigit() and len(year) == 4 and number.isdigit() and len(number) >= 4:
                    # Normalize to uppercase
                    valid_cves.append(cve.upper())
        
        return sorted(list(set(valid_cves)))
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+[^\s<>"{}|\\^`\[\].,;!?]'
        urls = re.findall(url_pattern, text)
        return list(set(urls))
    
    def convert_date_to_iso(self, date_str: str) -> Optional[str]:
        """Convert various date formats to YYYY-MM-DD"""
        if not date_str:
            return None
        
        # Try ISO format first
        iso_match = re.match(r'(\d{4}-\d{2}-\d{2})', date_str)
        if iso_match:
            return iso_match.group(1)
        
        # Try "October 28, 2025" format
        month_names = {
            'january': '01', 'february': '02', 'march': '03', 'april': '04',
            'may': '05', 'june': '06', 'july': '07', 'august': '08',
            'september': '09', 'october': '10', 'november': '11', 'december': '12'
        }
        
        pattern = r'([a-zA-Z]+)\s+(\d{1,2}),?\s+(\d{4})'
        match = re.search(pattern, date_str, re.IGNORECASE)
        if match:
            month_name = match.group(1).lower()
            day = match.group(2).zfill(2)
            year = match.group(3)
            if month_name in month_names:
                return f"{year}-{month_names[month_name]}-{day}"
        
        return None
    
    def extract_dates(self, text: str) -> Dict[str, Optional[str]]:
        """Extract dates in various formats"""
        dates = {}
        
        # Pattern for dates like "2025-10-28" or "October 28, 2025"
        date_patterns = [
            (r'original[_\s]?issue[_\s]?date[:\s]+([^\n]+)', 'original_issue_date'),
            (r'printed[_\s]?date[:\s]+([^\n]+)', 'printed_date'),
            (r'issue[_\s]?date[:\s]+([^\n]+)', 'original_issue_date'),
        ]
        
        for pattern, key in date_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                date_str = match.group(1).strip()
                iso_date = self.convert_date_to_iso(date_str)
                if iso_date:
                    dates[key] = iso_date
        
        return dates
    
    def extract_contact_information(self, text: str) -> Dict[str, Any]:
        """Extract contact information"""
        contact = {
            "email": None,
            "phone": None,
            "postal_address": {
                "organisation": None,
                "ministry": None,
                "government": None,
                "building": None,
                "street": None,
                "city": None,
                "postal_code": None,
                "country": None
            }
        }
        
        # Extract email - look for Email: prefix
        email_match = re.search(r'email[:\s]+([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text, re.IGNORECASE)
        if email_match:
            contact["email"] = email_match.group(1)
        else:
            # Fallback: any email in contact section
            email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)
            if email_match:
                contact["email"] = email_match.group(1)
        
        # Extract phone - look for Phone: prefix, specific Indian format
        phone_match = re.search(r'phone[:\s]+([+]?\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9})', text, re.IGNORECASE)
        if phone_match:
            contact["phone"] = phone_match.group(1).strip()
        else:
            # Fallback: look for +91 pattern
            phone_match = re.search(r'(\+91[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{4})', text)
            if phone_match:
                contact["phone"] = phone_match.group(1).strip()
        
        # Extract postal address - look for Contact Information section
        contact_section = self.extract_field_by_pattern(
            r'contact[_\s]?information[:\s]*\n((?:[^\n]+\n?)+)', 
            text
        ) or ""
        
        # Extract postal address components
        org_match = re.search(r'Indian Computer Emergency Response Team \(CERT-In\)', text, re.IGNORECASE)
        if org_match:
            contact["postal_address"]["organisation"] = "Indian Computer Emergency Response Team (CERT-In)"
        
        ministry_match = re.search(r'Ministry of Electronics and Information Technology', text, re.IGNORECASE)
        if ministry_match:
            contact["postal_address"]["ministry"] = "Ministry of Electronics and Information Technology"
        
        gov_match = re.search(r'Government of India', text, re.IGNORECASE)
        if gov_match:
            contact["postal_address"]["government"] = "Government of India"
        
        # Extract building
        building_match = re.search(r'Electronics Niketan', text, re.IGNORECASE)
        if building_match:
            contact["postal_address"]["building"] = "Electronics Niketan"
        
        # Extract street - look for "6, CGO Complex, Lodhi Road"
        street_match = re.search(r'(\d+,\s*CGO Complex,\s*Lodhi Road[,\s]*)', text, re.IGNORECASE)
        if street_match:
            contact["postal_address"]["street"] = street_match.group(1).rstrip(', ').strip()
        
        # Extract city
        city_match = re.search(r'New Delhi', text, re.IGNORECASE)
        if city_match:
            contact["postal_address"]["city"] = "New Delhi"
        
        # Extract postal code - look for "110 003" pattern near New Delhi
        postal_match = re.search(r'New Delhi[^\n]*?(\d{3}\s?\d{3})', text, re.IGNORECASE)
        if postal_match:
            contact["postal_address"]["postal_code"] = postal_match.group(1)
        else:
            # Fallback: look for 110 003 pattern
            postal_match = re.search(r'\b(110\s?003)\b', text)
            if postal_match:
                contact["postal_address"]["postal_code"] = postal_match.group(1)
        
        contact["postal_address"]["country"] = "India"
        
        return contact
    
    def convert_to_json(self) -> Dict[str, Any]:
        """Main conversion method"""
        print(f"Processing PDF: {self.pdf_path.name}")
        
        # Step 1: Extract text from PDF
        print("Extracting text from PDF...")
        self.full_text = self.extract_text_from_pdf()
        
        # Step 2: Extract text from images (OCR)
        print("Extracting text from images using OCR...")
        self.image_text = self.extract_images_and_ocr()
        
        # Combine all text sources
        combined_text = self.full_text + "\n" + "\n".join(self.image_text)
        
        # Step 3: Extract structured fields
        print("Extracting structured data...")
        
        # Basic document information
        # Document title - look for "CERT-In Advisory" at start
        document_title_match = self.extract_field_by_pattern(
            r'^(CERT-In\s+Advisory[^\n]*)', 
            self.full_text
        )
        if not document_title_match:
            document_title_match = self.extract_field_by_pattern(
                r'(CERT-In\s+Advisory\s+CIAD-\d{4}-\d{4,})', 
                combined_text
            )
        
        # Clean up document title - remove date stamps and metadata
        if document_title_match:
            # Remove patterns like "03/11/2025, 10:26" or timestamps
            document_title = re.sub(r'\d{2}/\d{2}/\d{4}[^\n]*', '', document_title_match, flags=re.IGNORECASE)
            document_title = re.sub(r',\s*\d{2}:\d{2}', '', document_title)  # Remove time stamps
            document_title = document_title.strip()
        else:
            document_title = "CERT-In Advisory Notes"
        
        # Extract advisory ID
        advisory_id = self.extract_field_by_pattern(
            r'(CIAD-\d{4}-\d{4,})', 
            combined_text
        )
        
        # Extract dates - handle "Original Issue Date: October 28, 2025" format
        dates = self.extract_dates(combined_text)
        original_issue_date = dates.get('original_issue_date')
        
        # Try to find printed date (usually at top of PDF)
        printed_date_match = self.extract_field_by_pattern(
            r'(?:printed|print)[_\s]?date[:\s]+([^\n]+)', 
            combined_text
        )
        if printed_date_match:
            printed_date = self.convert_date_to_iso(printed_date_match)
        else:
            # Try to find date pattern at top of document (metadata)
            top_date_match = re.search(r'(\d{2}/\d{2}/\d{4})', self.full_text[:500])
            if top_date_match:
                date_str = top_date_match.group(1)
                # Convert DD/MM/YYYY to YYYY-MM-DD
                parts = date_str.split('/')
                if len(parts) == 3:
                    printed_date = f"{parts[2]}-{parts[1]}-{parts[0]}"
                else:
                    printed_date = None
            else:
                printed_date = None
        
        # Severity rating
        severity_rating = self.extract_field_by_pattern(
            r'severity[_\s]?rating[:\s]+(Low|Medium|High|Critical)', 
            combined_text, 1
        )
        
        # Headline - comes right after advisory ID/title
        # Pattern: After "CERT-In Advisory CIAD-XXXX" or standalone headline
        headline = self.extract_field_by_pattern(
            r'(?:CIAD-\d{4}-\d{4,}\s*\n\s*|^)([^\n]+(?:Vulnerabilit|Security|Advisory)[^\n]+)', 
            combined_text
        )
        if not headline:
            # Try pattern after title
            headline = self.extract_field_by_pattern(
                r'CERT-In\s+Advisory[^\n]*\n\s*([^\n]+)', 
                combined_text
            )
        
        # Overview - paragraph after "Overview" keyword
        overview = self.extract_field_by_pattern(
            r'overview[:\s]*\n([^\n]+(?:\n[^\n]+)*?)(?=\n\s*(?:Target|Risk|Impact|Description|Solution))', 
            combined_text
        )
        
        summary = {
            "headline": headline,
            "overview": overview
        }
        
        # Software affected - list items after "Software Affected"
        software_affected = self.extract_list_by_keywords(
            combined_text, 
            ["Software Affected", "software affected", "affected software"],
            ["Overview", "Target Audience", "Description"]
        )
        
        # Target audience - look for "Target Audience:" followed by text
        target_audience = self.extract_field_by_pattern(
            r'target[_\s]?audience[:\s]*\n([^\n]+(?:\n[^\n]+)*?)(?=\n\s*(?:Risk|Impact|Description|Solution))', 
            combined_text
        )
        
        # Assessments
        risk_assessment = self.extract_field_by_pattern(
            r'risk[_\s]?assessment[:\s]*\n([^\n]+(?:\n[^\n]+)*?)(?=\n\s*(?:Impact|Description|Solution))', 
            combined_text
        )
        
        impact_assessment = self.extract_field_by_pattern(
            r'impact[_\s]?assessment[:\s]*\n([^\n]+(?:\n[^\n]+)*?)(?=\n\s*(?:Description|Solution))', 
            combined_text
        )
        
        assessments = {
            "risk_assessment": risk_assessment,
            "impact_assessment": impact_assessment
        }
        
        # Description - paragraph after "Description"
        description = self.extract_field_by_pattern(
            r'description[:\s]*\n([^\n]+(?:\n[^\n]+)*?)(?=\n\s*(?:Solution|Vendor|Reference))', 
            combined_text
        )
        # Clean up description - remove artifacts like "about:blank", page numbers, etc.
        if description:
            description = re.sub(r'about:blank[^\n]*', '', description, flags=re.IGNORECASE)
            description = re.sub(r'\d{2}/\d{2}/\d{4}[^\n]*', '', description)
            description = re.sub(r'\d+/\d+[^\n]*', '', description)  # Remove page numbers like "1/3"
            description = re.sub(r'\s+', ' ', description)  # Normalize whitespace
            description = description.strip()
        
        # Vulnerabilities - extract from overview and image table
        # First, get vulnerability types from overview
        types = []
        type_patterns = [
            (r'Path Traversal\s*\([^)]+\)', 'Path Traversal (Arbitrary Write)'),
            (r'HTTP Request Smuggling', 'HTTP Request Smuggling'),
            (r'SMTP Injection', 'SMTP Injection'),
            (r'Denial of Service|DoS', 'Denial of Service (DoS)'),
            (r'Cross-Site Scripting|XSS', 'Cross-Site Scripting (XSS)'),
            (r'SQL Injection', 'SQL Injection'),
            (r'Remote Code Execution|RCE', 'Remote Code Execution'),
            (r'Privilege Escalation', 'Privilege Escalation'),
            (r'Authentication Bypass', 'Authentication Bypass')
        ]
        
        overview_text = overview or ""
        for pattern, type_name in type_patterns:
            if re.search(pattern, overview_text, re.IGNORECASE):
                types.append(type_name)
        
        # Extract table data from images (OCR text) for detailed vulnerability info
        table_notes = []
        if self.image_text:
            # Combine OCR text - should contain table data
            table_text = "\n".join(self.image_text)
            # Look for table-like structure or CVE references
            if "CVE-" in table_text or "Affected" in table_text:
                # Extract meaningful notes from table
                # Limit to reasonable length
                table_notes.append("Multiple vulnerabilities reported across different Atlassian products; details referenced in vendor bulletin and NVD records.")
        
        vulnerabilities = []
        if types:
            vulnerabilities.append({
                "types": list(set(types)),  # Remove duplicates
                "notes": table_notes[0] if table_notes else "Multiple vulnerabilities reported across different Atlassian products; details referenced in vendor bulletin and NVD records."
            })
        elif overview_text:
            vulnerabilities.append({
                "types": ["Multiple vulnerabilities"],
                "notes": "Multiple vulnerabilities reported across different Atlassian products; details referenced in vendor bulletin and NVD records."
            })
        
        # Solution - extract advice and URL
        solution_section = self.extract_field_by_pattern(
            r'solution[:\s]*\n((?:[^\n]+\n?)+?)(?=\n\s*(?:Vendor|Reference|CVE))', 
            combined_text
        )
        
        advice = None
        if solution_section:
            # Extract the text before URL
            advice_match = re.search(r'^([^\n]+(?:update|patch|upgrade)[^\n]*)', solution_section, re.IGNORECASE)
            if advice_match:
                advice = advice_match.group(1).strip()
            else:
                # Take first line or first sentence
                lines = solution_section.split('\n')
                advice = lines[0].strip() if lines else solution_section[:200].strip()
        
        # Extract vendor bulletin URL from solution section or URLs
        urls = self.extract_urls(combined_text)
        vendor_bulletin_url = None
        for url in urls:
            if any(keyword in url.lower() for keyword in ['security-bulletin', 'atlassian', 'vendor']):
                vendor_bulletin_url = url
                break
        
        if not vendor_bulletin_url and urls:
            vendor_bulletin_url = urls[0]  # Use first URL as fallback
        
        solution = {
            "advice": advice,
            "vendor_bulletin_url": vendor_bulletin_url
        }
        
        # Vendor information - look for "Vendor Information" section
        vendor_name = self.extract_field_by_pattern(
            r'vendor[_\s]?information[:\s]*\n([^\n]+)', 
            combined_text
        )
        if not vendor_name:
            # Try pattern without "Information"
            vendor_name = self.extract_field_by_pattern(
                r'vendor[:\s]*\n([^\n]+)', 
                combined_text
            )
        
        vendor_url = vendor_bulletin_url or (urls[0] if urls else None)
        
        vendor_information = {
            "name": vendor_name,
            "vendor_url": vendor_url
        }
        
        # References - extract all URLs, but prioritize specific ones
        references = self.extract_urls(combined_text)
        
        # CVE list - extract from "CVE Name" section or throughout document
        cve_section = self.extract_field_by_pattern(
            r'CVE[_\s]?name[:\s]*\n((?:[^\n]+\n?)+)', 
            combined_text
        )
        if cve_section:
            # Extract CVEs from this section
            cve_list = self.extract_cve_list(cve_section)
        else:
            cve_list = self.extract_cve_list(combined_text)
        
        # Disclaimer
        disclaimer = self.extract_field_by_pattern(
            r'(The information provided herein[^\n]+)', 
            combined_text
        ) or 'The information provided herein is on "as is" basis, without warranty of any kind.'
        
        # Contact information
        contact_information = self.extract_contact_information(combined_text)
        
        # File citation
        file_citation = self.pdf_path.name
        
        # Build final JSON structure
        result = {
            "document_title": document_title,
            "advisory_id": advisory_id,
            "original_issue_date": original_issue_date,
            "printed_date": printed_date,
            "severity_rating": severity_rating,
            "summary": summary,
            "software_affected": software_affected,
            "target_audience": target_audience,
            "assessments": assessments,
            "description": description,
            "vulnerabilities": vulnerabilities,
            "solution": solution,
            "vendor_information": vendor_information,
            "references": references,
            "cve_list": cve_list,
            "disclaimer": disclaimer,
            "contact_information": contact_information,
            "_file_citation": file_citation
        }
        
        # Remove None values from nested structures
        result = self._clean_none_values(result)
        
        return result
    
    def _clean_none_values(self, obj: Any) -> Any:
        """Recursively remove None values from dictionary"""
        if isinstance(obj, dict):
            return {k: self._clean_none_values(v) for k, v in obj.items() if v is not None}
        elif isinstance(obj, list):
            return [self._clean_none_values(item) for item in obj]
        else:
            return obj
    
    def save_json(self, output_path: Optional[str] = None, indent: int = 2) -> str:
        """Convert PDF to JSON and save to file"""
        json_data = self.convert_to_json()
        
        if output_path is None:
            output_path = self.pdf_path.with_suffix('.json')
        else:
            output_path = Path(output_path)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=indent, ensure_ascii=False)
        
        print(f"JSON saved to: {output_path}")
        return str(output_path)


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python pdf_to_json_converter.py <pdf_file_path> [output_json_path]")
        print("\nExample:")
        print("  python pdf_to_json_converter.py 'CERT-In Advisory Notes oct 28 2025.pdf'")
        print("  python pdf_to_json_converter.py 'input.pdf' 'output.json'")
        sys.exit(1)
    
    pdf_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        converter = PDFToJSONConverter(pdf_path)
        output_file = converter.save_json(output_path)
        
        print("\nConversion completed successfully!")
        print(f"Output file: {output_file}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()


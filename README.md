# PDF to JSON Converter for CERT-In Advisory Notes

This script converts CERT-In Advisory PDF documents to structured JSON format, with support for extracting text from image-based tables using OCR.

## Features

- Extracts text content from PDF documents
- Performs OCR on image-based tables/figures within PDFs
- Structures extracted data into JSON format matching CERT-In advisory schema
- Handles various date formats, CVE identifiers, URLs, and contact information

## Requirements

### Python Dependencies

Install Python packages:
```bash
pip install -r requirements.txt
```

### System Dependencies

**Tesseract OCR** (required for image-based table extraction):

- **Ubuntu/Debian:**
  ```bash
  sudo apt-get install tesseract-ocr
  ```

- **macOS:**
  ```bash
  brew install tesseract
  ```

- **Windows:**
  Download and install from: https://github.com/UB-Mannheim/tesseract/wiki

## Usage

### Basic Usage

```bash
python pdf_to_json_converter.py <pdf_file_path>
```

The script will automatically create a JSON file with the same name as the PDF (with `.json` extension).

### Specify Output File

```bash
python pdf_to_json_converter.py <pdf_file_path> <output_json_path>
```

### Example

```bash
python pdf_to_json_converter.py "CERT-In Advisory Notes oct 28 2025.pdf"
# Output: CERT-In Advisory Notes oct 28 2025.json

python pdf_to_json_converter.py "input.pdf" "output.json"
```

## Output Structure

The JSON output follows this structure:

```json
{
  "document_title": "...",
  "advisory_id": "CIAD-YYYY-XXXX",
  "original_issue_date": "YYYY-MM-DD",
  "printed_date": "YYYY-MM-DD",
  "severity_rating": "High|Medium|Low|Critical",
  "summary": {
    "headline": "...",
    "overview": "..."
  },
  "software_affected": ["..."],
  "target_audience": "...",
  "assessments": {
    "risk_assessment": "...",
    "impact_assessment": "..."
  },
  "description": "...",
  "vulnerabilities": [...],
  "solution": {...},
  "vendor_information": {...},
  "references": [...],
  "cve_list": [...],
  "disclaimer": "...",
  "contact_information": {...},
  "_file_citation": "..."
}
```

## Notes

- The script uses pattern matching to extract structured data from PDFs. Extraction accuracy depends on PDF formatting consistency.
- Image-based tables are automatically detected and processed using OCR.
- If a field cannot be extracted, it may be `null` or omitted in the JSON output.
- The script handles common CERT-In document formats, but may need adjustments for unusual formatting.

## Troubleshooting

1. **OCR not working**: Ensure Tesseract OCR is installed and accessible in your system PATH.
2. **Missing fields**: Some fields may not be extracted if the PDF format differs from expected patterns. Review the PDF and adjust extraction patterns if needed.
3. **Import errors**: Make sure all Python dependencies are installed: `pip install -r requirements.txt`


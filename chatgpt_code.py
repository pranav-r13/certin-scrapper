import sys
import re
import json
from pathlib import Path

# ----------------------------
# Usage: python code.py "path/to/file.pdf"
# ----------------------------

if len(sys.argv) < 2:
    print("Usage: python code.py <pdf_file_path>")
    sys.exit(1)

pdf_path = Path(sys.argv[1])
if not pdf_path.exists():
    print(f"Error: File not found at {pdf_path}")
    sys.exit(1)

# Extract text from PDF
text_pages = []
try:
    import PyPDF2
    with open(pdf_path, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        for p in reader.pages:
            text_pages.append(p.extract_text() or "")
except Exception as e:
    print(f"Error reading PDF: {e}")
    sys.exit(1)

raw_text = "\n".join(text_pages)

def first(regex, text, flags=re.IGNORECASE):
    m = re.search(regex, text, flags)
    return m.group(1).strip() if m else None

data = {
    "source_file": str(pdf_path.name),
    "pages": [{"page": i + 1, "text": t} for i, t in enumerate(text_pages)],
    "parsed": {}
}

parsed = {}
parsed["title"] = first(r"^(CERT-In Advisory[^\n]*)", raw_text, flags=re.I | re.M) or first(r"^(CERT-In Advisory Notes[^\n]*)", raw_text, flags=re.I | re.M)
parsed["advisory_id"] = first(r"CERT-?In Advisory\s*([A-Z0-9\-\_]+)", raw_text) or first(r"CIAD[^\n]*", raw_text)
parsed["original_issue_date"] = first(r"Original Issue Date[:\s]*([^\n]+)", raw_text)
parsed["severity_rating"] = first(r"Severity Rating[:\s]*([^\n]+)", raw_text)

m = re.search(r"Software Affected\s*(.*?)\n(?:Overview|Description|Solution|Target Audience|Severity Rating|$)", raw_text, re.S | re.I)
if m:
    items = [s.strip(" .\t") for s in re.split(r"[\n,]+", m.group(1)) if s.strip()]
    parsed["software_affected"] = items
else:
    parsed["software_affected"] = []

parsed["overview"] = first(r"Overview\s*(.*?)\n\n", raw_text, re.S)
parsed["target_audience"] = first(r"Target Audience[:\s]*([^\n]+)", raw_text)
parsed["risk_assessment"] = first(r"Risk Assessment[:\s]*([^\n]+)", raw_text)
parsed["impact_assessment"] = first(r"Impact Assessment[:\s]*([^\n]+)", raw_text)

m = re.search(r"Description\s*(.*?)(?:Solution|Vendor Information|References|CVE Name|Disclaimer|Contact Information|$)", raw_text, re.S | re.I)
parsed["description"] = m.group(1).strip() if m else None

parsed["solution"] = first(r"Solution[:\s]*(.*?)(?:\n\n|Vendor Information|References|$)", raw_text, re.S)
parsed["vendor_information"] = first(r"Vendor Information[:\s]*(.*?)(?:\n\n|References|CVE|Disclaimer|$)", raw_text, re.S)

refs = re.findall(r"(https?://[^\s\)\]\"]+)", raw_text)
parsed["references"] = list(dict.fromkeys(refs))
parsed["cve_names"] = list(dict.fromkeys(re.findall(r"(CVE-\d{4}-\d+)", raw_text, re.I)))

# Removed contact_information and postal_address as requested

data["parsed"] = parsed

# Save output
out_path = pdf_path.with_suffix(".json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print(f"\n JSON saved at: {out_path}")
print(json.dumps({
    "title": parsed.get("title"),
    "advisory_id": parsed.get("advisory_id"),
    "software_affected_count": len(parsed.get("software_affected", [])),
    "cve_count": len(parsed.get("cve_names", [])),
    "references_count": len(parsed.get("references", []))
}, indent=2))

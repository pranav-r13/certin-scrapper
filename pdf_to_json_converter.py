#!/usr/bin/env python3
"""
PDF to JSON Converter for CERT-In Advisory Notes (Corrected, ready-to-run)

Features / fixes:
- Robust text extraction using pdfplumber, with table extraction.
- Image extraction using PyMuPDF (fitz) + OCR via pytesseract; sensible upscaling/preserving aspect ratio.
- Corrected CVE extraction (no placeholder), robust to common OCR noise.
- Corrected URL extraction regex and trailing-punctuation stripping.
- Improved date conversion to ISO (YYYY-MM-DD) with multiple format fallbacks.
- Cleaner normalization, logging (instead of prints), and defensive checks.
- Single-file runnable script. Save as e.g. `pdf_to_json_converter.py`.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional

# External deps: pdfplumber, Pillow (PIL), pytesseract, PyMuPDF (fitz)
try:
    import pdfplumber
    from PIL import Image
    import pytesseract
    import fitz  # PyMuPDF
except Exception as e:  # pragma: no cover
    sys.stderr.write(
        "Error: Missing required libraries. Install with:\n"
        "  pip install pdfplumber pillow pytesseract PyMuPDF\n"
    )
    sys.exit(1)


LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class PDFToJSONConverter:
    """Converts CERT-In-style advisory PDFs to structured JSON."""

    def __init__(self, pdf_path: str):
        self.pdf_path = Path(pdf_path)
        if not self.pdf_path.exists():
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")

        self.full_text: str = ""
        self.table_texts: List[str] = []
        self.image_texts: List[str] = []

    # ----------------------------
    # Extraction helpers
    # ----------------------------
    def extract_text_from_pdf(self) -> str:
        """Extract all textual content and simple table text using pdfplumber."""
        LOG.info("Extracting text and tables from PDF via pdfplumber...")
        pages_text: List[str] = []
        table_texts: List[str] = []

        with pdfplumber.open(self.pdf_path) as pdf:
            for page_no, page in enumerate(pdf.pages, start=1):
                try:
                    text = page.extract_text() or ""
                    pages_text.append(text)
                except Exception as exc:
                    LOG.warning("pdfplumber failed to extract text from page %d: %s", page_no, exc)
                    pages_text.append("")

                # extract any simple tables found by pdfplumber
                try:
                    tables = page.extract_tables() or []
                    for t in tables:
                        rows = [" | ".join([(cell or "").strip() for cell in r]) for r in t]
                        table_texts.append("\n".join(rows))
                except Exception:
                    # ignore table extraction errors for robustness
                    continue

        self.table_texts = [t for t in table_texts if t.strip()]
        combined = "\n".join(pages_text).strip()
        LOG.info("Finished text extraction. %d pages processed, %d table blocks found.",
                 len(pages_text), len(self.table_texts))
        return combined

    def extract_images_and_ocr(self) -> List[str]:
        """Extract images using PyMuPDF and run OCR with pytesseract."""
        LOG.info("Extracting embedded images via PyMuPDF and running OCR...")
        ocr_texts: List[str] = []

        try:
            doc = fitz.open(self.pdf_path)
        except Exception as exc:
            LOG.warning("PyMuPDF failed to open PDF: %s", exc)
            return ocr_texts

        for page_index in range(len(doc)):
            try:
                page = doc[page_index]
                images = page.get_images(full=True) or []
            except Exception:
                images = []

            for img_index, img_meta in enumerate(images, start=1):
                try:
                    xref = img_meta[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image.get("image")
                    if not image_bytes:
                        continue

                    pil_img = Image.open(BytesIO(image_bytes)).convert("RGB")
                    w, h = pil_img.size
                    # Upscale small images to help OCR, preserving aspect ratio
                    min_dim = 800
                    if w < min_dim or h < min_dim:
                        scale = max(min_dim / max(w, 1), min_dim / max(h, 1))
                        new_w = int(w * scale)
                        new_h = int(h * scale)
                        pil_img = pil_img.resize((new_w, new_h), Image.LANCZOS)

                    # Pass through pytesseract
                    ocr_result = pytesseract.image_to_string(pil_img)
                    if ocr_result and ocr_result.strip():
                        cleaned = re.sub(r'\r\n?', '\n', ocr_result).strip()
                        ocr_texts.append(cleaned)
                        LOG.debug("OCR extracted text from page %d image %d (len=%d)", page_index + 1, img_index, len(cleaned))
                except Exception as exc:
                    LOG.debug("Skipping image %d on page %d due to error: %s", img_index, page_index + 1, exc)
                    continue

        try:
            doc.close()
        except Exception:
            pass

        self.image_texts = ocr_texts
        LOG.info("Finished OCR: %d image text blocks extracted.", len(ocr_texts))
        return ocr_texts

    # ----------------------------
    # Utility extraction functions
    # ----------------------------
    def extract_field_by_pattern(self, pattern: str, text: str, group: int = 1) -> Optional[str]:
        """Regex-based extraction; returns normalized string or None."""
        if not text:
            return None
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE | re.DOTALL)
        if not m:
            return None
        value = m.group(group).strip()
        value = re.sub(r'\s+', ' ', value)
        return value or None

    def extract_list_by_keyword_block(self, text: str, start_keywords: List[str], stop_keywords: List[str]) -> List[str]:
        """
        Given a block start (one of start_keywords), extract lines until a stop keyword appears.
        Returns cleaned list items.
        """
        if not text:
            return []
        start_regex = r'(' + '|'.join(re.escape(k) for k in start_keywords) + r')[:\s]*'
        m = re.search(start_regex, text, re.IGNORECASE)
        if not m:
            return []

        start_pos = m.end()
        stop_regex = r'\n\s*(?:' + '|'.join(re.escape(k) for k in stop_keywords) + r')\b'
        stop_m = re.search(stop_regex, text[start_pos:], re.IGNORECASE)
        block = text[start_pos: start_pos + stop_m.start()] if stop_m else text[start_pos:]

        lines = [re.sub(r'^[\s\-\u2022\*\d\.\)]+', '', l).strip() for l in block.splitlines()]
        items = [l for l in lines if l and len(l) > 1]
        return items

    def extract_cve_list(self, text: str) -> List[str]:
        """Robust CVE extraction tolerant to OCR noise. Returns sorted unique CVEs."""
        if not text:
            return []

        # Normalize common OCR artifacts
        norm = text.replace('C/E', 'CVE').replace(r'C\VE', 'CVE').replace('CV E', 'CVE').replace('C V E', 'CVE')
        # Capture patterns like CVE-2025-1234, CVE 2025 1234567, CVE2025-1234
        matches = re.findall(r'\bCVE[-\s]?(20\d{2})[-\s]?(\d{4,7})\b', norm, flags=re.IGNORECASE)
        normalized = []
        for year, num in matches:
            if year.isdigit() and num.isdigit():
                normalized.append(f"CVE-{year}-{num}")

        # Dedupe and sort: by year then number
        def _key(cve: str):
            try:
                _, y, n = cve.split('-')
                return (int(y), int(n))
            except Exception:
                return (0, 0)

        unique_sorted = sorted(set([c.upper() for c in normalized]), key=_key)
        return unique_sorted

    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs and strip trailing punctuation commonly added by PDFs."""
        if not text:
            return []
        raw = re.findall(r'https?://[^\s<>"\]\)\(]+', text)
        out: List[str] = []
        seen = set()
        for u in raw:
            u = u.rstrip('.,;:!?)\\]}\'"')
            if u and u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def convert_date_to_iso(self, date_str: str) -> Optional[str]:
        """Attempt to convert many human date formats to YYYY-MM-DD (ISO)."""
        if not date_str:
            return None
        s = date_str.strip()
        # Try direct ISO
        try:
            return datetime.fromisoformat(s).date().isoformat()
        except Exception:
            pass

        # Candidate formats
        formats = [
            "%B %d, %Y", "%d %B %Y", "%d %b %Y", "%b %d, %Y",
            "%d/%m/%Y", "%m/%d/%Y", "%Y-%m-%d", "%d-%m-%Y"
        ]
        for fmt in formats:
            try:
                return datetime.strptime(s, fmt).date().isoformat()
            except Exception:
                continue

        # Try regex extraction: "28 October 2025" or "October 28, 2025"
        m = re.search(r'(\d{1,2})[^\dA-Za-z]{0,3}([A-Za-z]+)[^\dA-Za-z]{0,3}(20\d{2})', s)
        if m:
            d, mon, y = m.group(1), m.group(2), m.group(3)
            try:
                month = datetime.strptime(mon[:3], "%b").month
                return f"{y}-{month:02d}-{int(d):02d}"
            except Exception:
                pass

        # dd/mm/yyyy fallback
        m2 = re.search(r'(\d{1,2})/(\d{1,2})/(\d{4})', s)
        if m2:
            d, mo, y = m2.groups()
            return f"{y}-{int(mo):02d}-{int(d):02d}"

        return None

    # ----------------------------
    # Main conversion
    # ----------------------------
    def convert_to_json(self) -> Dict[str, Any]:
        """Convert the loaded PDF to a structured JSON-serializable dictionary."""
        LOG.info("Starting conversion for: %s", self.pdf_path.name)
        # Extract text, tables and images
        self.full_text = self.extract_text_from_pdf() or ""
        # extract images/ocr
        self.extract_images_and_ocr()

        # Create a combined search space
        combined_text = "\n".join([self.full_text, "\n".join(self.table_texts), "\n".join(self.image_texts)]).strip()

        # Document title heuristics
        document_title = self.extract_field_by_pattern(r'^(CERT[-\s]?In\s+Advisory[^\n]*)', self.full_text) \
            or self.extract_field_by_pattern(r'^(CERT[-\s]?In[^\n]+)', self.full_text) \
            or "CERT-In Advisory Notes"

        # Advisory ID (CIAD-YYYY-NNNN or similar)
        advisory_id = self.extract_field_by_pattern(r'\b(CIAD[-\s]?\d{4}[-\s]?\d{2,6})\b', combined_text)
        if advisory_id:
            advisory_id = advisory_id.replace(' ', '').replace('_', '-')

        # Dates
        original_issue_date_raw = self.extract_field_by_pattern(r'Original\s+Issue\s+Date[:\s]*([^\n]+)', combined_text) \
            or self.extract_field_by_pattern(r'Issue\s+Date[:\s]*([^\n]+)', combined_text)
        original_issue_date = self.convert_date_to_iso(original_issue_date_raw) if original_issue_date_raw else None

        printed_date_raw = self.extract_field_by_pattern(r'Printed\s+Date[:\s]*([^\n]+)', combined_text) \
            or self.extract_field_by_pattern(r'Print\s+Date[:\s]*([^\n]+)', combined_text)
        printed_date = self.convert_date_to_iso(printed_date_raw) if printed_date_raw else None

        # If printed_date still missing, look at top-of-doc dd/mm/yyyy
        if not printed_date and self.full_text:
            top_segment = self.full_text[:400]
            m = re.search(r'(\d{1,2}/\d{1,2}/\d{4})', top_segment)
            if m:
                printed_date = self.convert_date_to_iso(m.group(1))

        # Severity (Single-word rating)
        severity_rating = self.extract_field_by_pattern(r'\bSeverity[:\s]*\n?([A-Za-z]+)\b', combined_text)
        if severity_rating:
            severity_rating = severity_rating.capitalize()

        # Summary: headline + overview
        headline = self.extract_field_by_pattern(
            r'(?:CIAD[-\s]?\d{4}[-\s]?\d{2,6}\b.*\n)?(.{10,200}?(?:Vulnerab|Security|Advisory|Atlassian|Multiple)[^\n]*)',
            combined_text
        )
        overview = self.extract_field_by_pattern(r'Overview[:\s]*\n([^\n]+(?:\n[^\n]+)*)', combined_text) \
            or self.extract_field_by_pattern(r'Summary[:\s]*\n([^\n]+(?:\n[^\n]+)*)', combined_text)

        summary = {"headline": headline, "overview": overview}

        # Software affected
        software_affected = self.extract_list_by_keyword_block(
            combined_text,
            start_keywords=["Software Affected", "Affected Software", "Software affected"],
            stop_keywords=["Overview", "Target Audience", "Description", "Solution", "Vendor", "References"]
        )

        # Target audience and assessments
        target_audience = self.extract_field_by_pattern(r'Target\s+Audience[:\s]*\n([^\n]+(?:\n[^\n]+)*)', combined_text)
        risk_assessment = self.extract_field_by_pattern(r'Risk\s+Assessment[:\s]*\n([^\n]+(?:\n[^\n]+)*)', combined_text)
        impact_assessment = self.extract_field_by_pattern(r'Impact\s+Assessment[:\s]*\n([^\n]+(?:\n[^\n]+)*)', combined_text)
        assessments = {"risk_assessment": risk_assessment, "impact_assessment": impact_assessment}

        # Description
        description = self.extract_field_by_pattern(r'Description[:\s]*\n([^\n]+(?:\n[^\n]+)*)', combined_text)
        if description:
            description = re.sub(r'\s+', ' ', description).strip()

        # Vulnerabilities: detect known types in combined text
        type_map = {
            r'Path Traversal': 'Path Traversal (Arbitrary Write)',
            r'HTTP Request Smuggling': 'HTTP Request Smuggling',
            r'SMTP Injection': 'SMTP Injection',
            r'Denial of Service|DoS': 'Denial of Service (DoS)',
            r'Cross[-\s]?Site Scripting|XSS': 'Cross-Site Scripting (XSS)',
            r'SQL Injection': 'SQL Injection',
            r'Remote Code Execution|RCE': 'Remote Code Execution',
            r'Privilege Escalation': 'Privilege Escalation',
            r'Authentication Bypass': 'Authentication Bypass'
        }
        search_space = " ".join([combined_text, " ".join(self.table_texts), " ".join(self.image_texts)])
        vulnerability_types: List[str] = []
        for pat, name in type_map.items():
            if re.search(pat, search_space, re.IGNORECASE):
                vulnerability_types.append(name)

        vulnerability_notes = None
        if self.table_texts:
            vulnerability_notes = "Table(s) detected in PDF with vulnerability details; check 'references' for vendor/NVD links."
        elif self.image_texts:
            vulnerability_notes = "OCR'd image text suggests tabular vulnerability details; check 'references' for vendor/NVD links."
        else:
            vulnerability_notes = "Multiple vulnerabilities reported across products; see vendor bulletin and NVD entries."

        vulnerabilities = []
        if vulnerability_types:
            vulnerabilities.append({"types": sorted(list(set(vulnerability_types))), "notes": vulnerability_notes})
        else:
            vulnerabilities.append({"types": ["Multiple vulnerabilities"], "notes": vulnerability_notes})

        # Solution / remediation & vendor bulletin URL
        solution_block = self.extract_field_by_pattern(r'Solution[:\s]*\n([^\n]+(?:\n[^\n]+)*)', combined_text) \
            or self.extract_field_by_pattern(r'Remediation[:\s]*\n([^\n]+(?:\n[^\n]+)*)', combined_text)

        advice = None
        if solution_block:
            m = re.search(r'([^.]{0,200}\b(update|patch|upgrade|apply|mitigat)\b[^.]*)\.', solution_block, re.IGNORECASE)
            advice = (m.group(0).strip() if m else solution_block.splitlines()[0].strip())

        urls = self.extract_urls(combined_text)
        vendor_bulletin_url = None
        for u in urls:
            if any(k in u.lower() for k in ('atlassian', 'security-bulletin', 'vendor', 'cert-in', 'nvd.nist')):
                vendor_bulletin_url = u
                break
        if not vendor_bulletin_url and urls:
            vendor_bulletin_url = urls[0]  # fallback

        solution = {"advice": advice, "vendor_bulletin_url": vendor_bulletin_url}

        # Vendor information
        vendor_name = self.extract_field_by_pattern(r'Vendor\s+Information[:\s]*\n([^\n]+)', combined_text) \
            or self.extract_field_by_pattern(r'Vendor[:\s]*\n([^\n]+)', combined_text)
        vendor_information = {"name": vendor_name, "vendor_url": vendor_bulletin_url}

        # References (URLs) and CVEs
        references = urls
        cve_list = self.extract_cve_list(combined_text)

        # Disclaimer
        disclaimer = self.extract_field_by_pattern(r'(The information provided herein[^\n]+\.)', combined_text) \
            or 'The information provided herein is on "as is" basis, without warranty of any kind.'

        # Contact info heuristics
        contact = {"email": None, "phone": None, "postal_address": {}}
        em = re.search(r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})', combined_text)
        if em:
            contact["email"] = em.group(1)
        ph = re.search(r'(\+?\d{1,3}[-\s]?\d{2,4}[-\s]?\d{3,4}[-\s]?\d{3,4})', combined_text)
        if ph:
            contact["phone"] = ph.group(1).strip()
        if re.search(r'Indian Computer Emergency Response Team', combined_text, re.IGNORECASE):
            contact["postal_address"]["organisation"] = "Indian Computer Emergency Response Team (CERT-In)"
        if re.search(r'Ministry of Electronics and Information Technology', combined_text, re.IGNORECASE):
            contact["postal_address"]["ministry"] = "Ministry of Electronics and Information Technology"
        if re.search(r'Electronics Niketan', combined_text, re.IGNORECASE):
            contact["postal_address"]["building"] = "Electronics Niketan"
        # Extract street address
        street_match = re.search(r'(\d+,\s*CGO Complex,\s*Lodhi Road)', combined_text, re.IGNORECASE)
        if street_match:
            contact["postal_address"]["street"] = street_match.group(1).rstrip(', ').strip()
        if re.search(r'New Delhi', combined_text, re.IGNORECASE):
            contact["postal_address"]["city"] = "New Delhi"
        if re.search(r'Government of India', combined_text, re.IGNORECASE):
            contact["postal_address"]["government"] = "Government of India"
        pc = re.search(r'\b(\d{3}\s?\d{3})\b', combined_text)
        if pc:
            contact["postal_address"]["postal_code"] = pc.group(1)
        contact["postal_address"]["country"] = "India"

        # Build final JSON structure
        result: Dict[str, Any] = {
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
            "contact_information": contact,
            "_file_citation": str(self.pdf_path.name)
        }

        cleaned = self._clean_none_values(result)
        LOG.info("Conversion complete. Fields extracted: document_title=%s, advisory_id=%s, cves=%d",
                 cleaned.get("document_title"), cleaned.get("advisory_id"), len(cleaned.get("cve_list", [])))
        return cleaned

    def _clean_none_values(self, obj: Any) -> Any:
        """Recursively remove None values and empty strings from dicts/lists (but keep empty lists)."""
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                v2 = self._clean_none_values(v)
                if v2 is None:
                    continue
                if isinstance(v2, str) and v2.strip() == "":
                    continue
                out[k] = v2
            return out
        elif isinstance(obj, list):
            return [self._clean_none_values(i) for i in obj if i is not None and not (isinstance(i, str) and i.strip() == "")]
        else:
            return obj

    def save_json(self, output_path: Optional[str] = None, indent: int = 2) -> str:
        """Convert to JSON and write to file. Returns output path as string."""
        data = self.convert_to_json()
        if output_path is None:
            output_path = self.pdf_path.with_suffix('.json')
        else:
            output_path = Path(output_path)

        with open(output_path, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=indent, ensure_ascii=False)

        LOG.info("Saved JSON to: %s", output_path)
        return str(output_path)


# ----------------------------
# CLI entry point
# ----------------------------
def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python pdf_to_json_converter.py <pdf_file_path> [output_json_path]\n")
        sys.exit(1)

    pdf_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        conv = PDFToJSONConverter(pdf_path)
        out = conv.save_json(output_path)
        print(out)
    except Exception as exc:
        LOG.exception("Failed to convert PDF: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()

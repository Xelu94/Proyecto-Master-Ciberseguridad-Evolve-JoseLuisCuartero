import os
import io
from pathlib import Path


def parse_file(file_path: str, filename: str) -> str:
    """Extract text from PDF, ODT, or TXT file."""
    ext = Path(filename).suffix.lower()
    if ext == ".pdf":
        return _parse_pdf(file_path)
    elif ext == ".odt":
        return _parse_odt(file_path)
    elif ext in (".txt", ".md", ".log"):
        return _parse_text(file_path)
    else:
        return _parse_text(file_path)


def _parse_pdf(path: str) -> str:
    try:
        import pdfplumber
        text_parts = []
        with pdfplumber.open(path) as pdf:
            for page in pdf.pages:
                t = page.extract_text()
                if t:
                    text_parts.append(t)
        return "\n\n".join(text_parts)
    except ImportError:
        return "[Error: pdfplumber not installed. Run: pip install pdfplumber]"
    except Exception as e:
        return f"[Error parsing PDF: {e}]"


def _parse_odt(path: str) -> str:
    try:
        from odf import text as odf_text, teletype
        from odf.opendocument import load as odf_load
        doc = odf_load(path)
        parts = []
        for para in doc.getElementsByType(odf_text.P):
            t = teletype.extractText(para)
            if t.strip():
                parts.append(t)
        return "\n\n".join(parts)
    except ImportError:
        return "[Error: odfpy not installed. Run: pip install odfpy]"
    except Exception as e:
        return f"[Error parsing ODT: {e}]"


def _parse_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return f"[Error reading file: {e}]"

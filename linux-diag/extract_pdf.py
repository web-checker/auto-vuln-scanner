from pathlib import Path
from PyPDF2 import PdfReader

path = Path(r'C:/Users/ez/ai-vuln-scanner/guideline/01_Unix_서버.pdf')
pdf = PdfReader(path)
print('PAGES', len(pdf.pages))
for i, page in enumerate(pdf.pages, 1):
    text = page.extract_text() or ''
    print(f'---PAGE {i}---')
    print(text[:4000])

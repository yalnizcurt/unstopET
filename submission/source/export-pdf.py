"""Assemble the checked final slide renders into a static submission PDF."""
import argparse
import json
from pathlib import Path
from reportlab.pdfgen.canvas import Canvas
from reportlab.lib.utils import ImageReader
from pypdf import PdfReader

parser = argparse.ArgumentParser()
parser.add_argument("renders", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
images = sorted(args.renders.glob("slide-*.png"), key=lambda path: int(path.stem.split("-")[-1]))
assert len(images) == 12, "The submission requires exactly twelve rendered slides"
args.output.parent.mkdir(parents=True, exist_ok=True)
pdf = Canvas(str(args.output), pagesize=(960, 540))
pdf.setTitle("Agent Trust Firewall: Hackathon Presentation")
identity = json.loads((Path(__file__).resolve().parents[1] / "pitch/deck-data.json").read_text())
pdf.setAuthor(identity["team_name"])
pdf.setSubject("Scoped prototype, measured results and known detection gaps")
for index, image in enumerate(images, start=1):
    pdf.drawImage(ImageReader(image), 0, 0, width=960, height=540)
    if index == 12:
        pdf.linkURL("https://agent-trust-firewall.vercel.app", (522, 193.5, 908.25, 234), relative=0)
        pdf.linkURL("https://github.com/yalnizcurt/unstopET", (522, 87, 908.25, 127.5), relative=0)
    pdf.showPage()
pdf.save()
reader = PdfReader(args.output)
assert len(reader.pages) == 12
assert all(tuple(map(float, page.mediabox[2:])) == (960.0, 540.0) for page in reader.pages)
print({"pdf": str(args.output), "pages": len(reader.pages), "editable_source": "Companion PPTX", "pdf_type": "static rendered slides"})

"""Inert extraction adapters used only in a restricted, credential-free worker."""
import base64
import hashlib
import io
import json
import re
import secrets
import zipfile
from pathlib import PurePosixPath
from html.parser import HTMLParser
from defusedxml import ElementTree as XML
from pypdf import PdfReader
from PIL import Image

MAX_FILE = 1_048_576
MAX_EXPANDED = 2_097_152
Image.MAX_IMAGE_PIXELS = 8_000_000

class Budget:
    def __init__(self): self.bytes=0; self.files=0; self.fragments=0; self.text=0
    def charge(self, size):
        self.bytes += size; self.files += 1
        if self.bytes > MAX_EXPANDED or self.files > 32: raise ValueError('EXTRACTION_BUDGET_EXHAUSTED')

class HTML(HTMLParser):
    def __init__(self, add): super().__init__(convert_charrefs=True); self.add=add; self.tags=[]
    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for key, value in attrs:
            if value: self.add('attributes', f'{tag}@{key}', value)
        if tag in ('script','iframe','object','embed'): self.add.gaps.append('active_or_embedded_'+tag)
    def handle_endtag(self, tag):
        if self.tags and tag in self.tags: self.tags=self.tags[:len(self.tags)-1-self.tags[::-1].index(tag)]
    def handle_data(self, data): self.add('static_text', '/'.join(self.tags), data)
    def handle_comment(self, data): self.add('comments', 'comment', data)


def extract(name, raw, budget=None, depth=0):
    budget = budget or Budget(); budget.charge(len(raw))
    result=dict(id=secrets.token_hex(12), filename=name[:180], sha256=hashlib.sha256(raw).hexdigest(),
                media_type='application/octet-stream', fragments=[], children=[], gaps=[], status='COMPLETE')
    def add(channel, location, value):
        for line, part in enumerate(str(value).splitlines()):
            if not part.strip(): continue
            budget.fragments += 1; budget.text += len(part.encode())
            if budget.fragments > 400 or budget.text > 40_000: raise ValueError('TEXT_BUDGET_EXHAUSTED')
            if len(part.encode()) > 8000: raise ValueError('FRAGMENT_BUDGET_EXHAUSTED')
            result['fragments'].append(dict(id=secrets.token_hex(8), channel=channel,
                location=f'{name}:{location}:line{line+1}', text=part))
    add.gaps=result['gaps']
    ext=PurePosixPath(name.lower()).suffix
    if len(raw)>MAX_FILE: raise ValueError('FILE_TOO_LARGE')
    if raw.startswith(b'%PDF-') and ext=='.pdf':
        result['media_type']='application/pdf'
        reader=PdfReader(io.BytesIO(raw), strict=True)
        if reader.is_encrypted: raise ValueError('ENCRYPTED_PDF_UNSUPPORTED')
        if len(reader.pages)>12: raise ValueError('PAGE_BUDGET_EXHAUSTED')
        for key,val in (reader.metadata or {}).items(): add('metadata',key,val)
        for i,page in enumerate(reader.pages):
            content=page.get_contents()
            if content and len(content.get_data())>MAX_EXPANDED: raise ValueError('PDF_STREAM_BUDGET_EXHAUSTED')
            value=page.extract_text() or ''
            add('page_text',f'page{i+1}',value)
            if not value.strip(): result['gaps'].append(f'page{i+1}:no_text_or_ocr')
            if page.get('/Resources',{}).get('/XObject'): result['gaps'].append(f'page{i+1}:xobjects_ocr_or_forms')
            for annot in page.get('/Annots',[]):
                obj=annot.get_object()
                for key in ('/Contents','/T','/Subj','/RC'): 
                    if key in obj: add('annotations',f'page{i+1}{key}',obj[key])
                if obj.get('/A') or obj.get('/FS'): result['gaps'].append(f'page{i+1}:annotation_action_or_attachment')
        root=reader.trailer['/Root']
        for key in ('/Names','/OpenAction','/AA','/AcroForm','/Metadata'):
            if key in root: result['gaps'].append('pdf:'+key)
    elif raw.startswith(b'PK\x03\x04') and ext in ('.zip','.docx','.xlsx'):
        archive=zipfile.ZipFile(io.BytesIO(raw)); infos=archive.infolist()
        if len(infos)>32 or sum(i.file_size for i in infos)>MAX_EXPANDED: raise ValueError('ARCHIVE_BUDGET_EXHAUSTED')
        for i in infos:
            if i.flag_bits&1 or i.file_size>MAX_FILE or i.file_size>max(1,i.compress_size)*100 or i.filename.startswith('/') or '..' in PurePosixPath(i.filename).parts:
                raise ValueError('UNSAFE_ARCHIVE_MEMBER')
        members=set(archive.namelist())
        if ext in ('.docx','.xlsx'):
            if '[Content_Types].xml' not in members or ('word/document.xml' if ext=='.docx' else 'xl/workbook.xml') not in members:
                raise ValueError('MIME_MISMATCH')
            result['media_type']='application/vnd.openxmlformats-officedocument.'+('wordprocessingml.document' if ext=='.docx' else 'spreadsheetml.sheet')
            shared=[]
            if 'xl/sharedStrings.xml' in members:
                root=XML.fromstring(archive.read('xl/sharedStrings.xml'))
                shared=[''.join(node.itertext()) for node in root]
            for i in infos:
                if i.is_dir(): continue
                data=archive.read(i)
                if i.filename.endswith(('.xml','.rels')):
                    root=XML.fromstring(data)
                    channel='comments' if 'comment' in i.filename else 'metadata' if i.filename.startswith('docProps/') else 'relationships' if i.filename.endswith('.rels') else 'body' if ext=='.docx' else 'workbook'
                    if '/worksheets/' in i.filename:
                        for cell in root.iter():
                            if cell.tag.split('}')[-1]!='c': continue
                            values=[n.text or '' for n in cell.iter() if n.tag.split('}')[-1] in ('v','t','f')]
                            if cell.get('t')=='s':
                                values=[shared[int(values[0])]] if values and 0<=int(values[0])<len(shared) else []
                            add('cells',i.filename+'!'+cell.get('r','?'),' | '.join(values))
                    else:
                        for j,node in enumerate(root.iter()):
                            if node.text and node.text.strip(): add(channel,f'{i.filename}:node{j}',node.text)
                            for key,value in node.attrib.items():
                                if key.split('}')[-1] in ('name','state','Target','descr','title','author','hidden'):
                                    add(channel,f'{i.filename}:node{j}@{key}',value)
                    if any(n.tag.split('}')[-1] in ('oleObject','object','drawing','pict','altChunk') for n in root.iter()): result['gaps'].append(i.filename+':embedded_or_drawing_content')
                else: result['gaps'].append(i.filename+':unsupported_embedded_content')
        else:
            result['media_type']='application/zip'
            if depth>=2: raise ValueError('NESTING_BUDGET_EXHAUSTED')
            for i in infos:
                if i.is_dir(): continue
                add('filenames',i.filename,i.filename)
                child=extract(i.filename,archive.read(i),budget,depth+1)
                result['children'].append(dict(id=child['id'],filename=child['filename'],sha256=child['sha256'],status=child['status'],gaps=child['gaps']))
                result['fragments'].extend(child['fragments'])
                result['gaps'].extend(child['gaps'])
                if child['status']=='UNSUPPORTED': result['gaps'].append(i.filename+':unsupported_child')
    elif ext in ('.png','.jpg','.jpeg') and (raw.startswith(b'\x89PNG\r\n\x1a\n') or raw.startswith(b'\xff\xd8\xff')):
        image=Image.open(io.BytesIO(raw)); image.verify()
        image=Image.open(io.BytesIO(raw))
        result['media_type']='image/'+('png' if image.format=='PNG' else 'jpeg')
        for key,value in image.info.items():
            if isinstance(value,str): add('metadata',str(key),value[:8000])
            elif isinstance(value,bytes) and key not in ('icc_profile','exif'): add('metadata',str(key),value.decode('utf-8','replace')[:8000])
        for key,value in image.getexif().items():
            if isinstance(value,str): add('metadata',str(key),value[:8000])
        result['gaps'].extend(['pixel_text_ocr_not_enabled','qr_codes_not_enabled'])
    elif ext in ('.txt','.md','.py','.js','.ts','.json','.csv','.html','.htm'):
        value=raw.decode('utf-8-sig',errors='strict')
        if '\x00' in value: raise ValueError('BINARY_TEXT_DENIED')
        result['media_type']='text/html' if ext in ('.html','.htm') else 'text/plain'
        if result['media_type']=='text/html': parser=HTML(add); parser.feed(value); parser.close()
        else: add('text','body',value)
    else: result['status']='UNSUPPORTED'; result['gaps'].append('unsupported_media_or_magic_mismatch')
    if not result['fragments'] and result['status']!='UNSUPPORTED': result['gaps'].append('no_extracted_content')
    if result['gaps'] and result['status']!='UNSUPPORTED': result['status']='PARTIAL'
    return result

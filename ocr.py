"""Fixed English OCR through a preloaded native library; no subprocess or shell capability."""
import ctypes
import os
from pathlib import Path

LIB=None
TESSDATA='/usr/share/tesseract-ocr/5/tessdata'


def initialize():
    global LIB
    if LIB is not None: return
    if os.environ.get('OMP_THREAD_LIMIT')!='1': raise RuntimeError('OCR_THREAD_BUDGET_REQUIRED')
    LIB=ctypes.CDLL('libtesseract.so.5')
    LIB.TessBaseAPICreate.restype=ctypes.c_void_p
    LIB.TessBaseAPIInit3.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_char_p]
    LIB.TessBaseAPIInit3.restype=ctypes.c_int
    LIB.TessBaseAPISetImage.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int]
    LIB.TessBaseAPISetPageSegMode.argtypes=[ctypes.c_void_p,ctypes.c_int]
    LIB.TessBaseAPIRecognize.argtypes=[ctypes.c_void_p,ctypes.c_void_p]
    LIB.TessBaseAPIRecognize.restype=ctypes.c_int
    LIB.TessBaseAPIGetUTF8Text.argtypes=[ctypes.c_void_p]
    LIB.TessBaseAPIGetUTF8Text.restype=ctypes.c_void_p
    LIB.TessDeleteText.argtypes=[ctypes.c_void_p]
    LIB.TessBaseAPIDelete.argtypes=[ctypes.c_void_p]


def recognize(image):
    if LIB is None: raise RuntimeError('OCR_LIBRARY_NOT_PRELOADED')
    api=LIB.TessBaseAPICreate()
    if not api: raise ValueError('OCR_UNAVAILABLE')
    output=None
    try:
        if LIB.TessBaseAPIInit3(api,TESSDATA.encode(),b'eng'): raise ValueError('OCR_INIT_FAILED')
        rgb=image.convert('RGB');pixels=ctypes.create_string_buffer(rgb.tobytes())
        LIB.TessBaseAPISetImage(api,pixels,rgb.width,rgb.height,3,rgb.width*3)
        LIB.TessBaseAPISetPageSegMode(api,6)
        if LIB.TessBaseAPIRecognize(api,None): raise ValueError('OCR_FAILED')
        output=LIB.TessBaseAPIGetUTF8Text(api)
        if not output: return ''
        value=ctypes.string_at(output)
        if len(value)>16_384: raise ValueError('OCR_TEXT_BUDGET_EXHAUSTED')
        return value.decode('utf-8',errors='strict')
    finally:
        if output: LIB.TessDeleteText(output)
        LIB.TessBaseAPIDelete(api)

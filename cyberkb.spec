# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('index.html', '.'),
        ('.env.example', '.'),
    ],
    hiddenimports=[
        # FastAPI / Starlette
        'fastapi',
        'starlette',
        'starlette.middleware',
        'starlette.middleware.cors',
        'starlette.responses',
        'starlette.routing',
        'starlette.staticfiles',
        # Uvicorn
        'uvicorn',
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        # SQLAlchemy
        'sqlalchemy',
        'sqlalchemy.dialects.sqlite',
        'sqlalchemy.ext.declarative',
        'sqlalchemy.orm',
        # Pydantic
        'pydantic',
        'pydantic_core',
        # Anthropic
        'anthropic',
        # PDF / ODT
        'pdfplumber',
        'pdfminer',
        'pdfminer.six',
        'odf',
        'odf.opendocument',
        'odf.text',
        'odf.teletype',
        # OSINT
        'whois',
        'dns',
        'dns.resolver',
        # HTTP
        'httpx',
        'httpcore',
        # Other
        'aiofiles',
        'multipart',
        'python_multipart',
        'dotenv',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'scipy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CyberKB',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # keep True so errors are visible
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

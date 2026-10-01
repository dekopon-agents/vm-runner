#!/bin/sh
set -eu
[ "$(id -u)" = 1000 ]
uv --version | grep -Ex 'uv 0\.12\.21( \([^)]*\))?'
[ "$(uv cache dir)" = /home/jail/.cache/uv ]
work=$(mktemp -d /home/jail/toolkit-smoke.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
export UV_CACHE_DIR="$work/cache"
mkdir -p "$UV_CACHE_DIR"
printf writable > "$UV_CACHE_DIR/probe"
cd "$work"
python3 - <<'PY'
import json, pathlib, sys, zipfile
assert sys.executable == '/usr/bin/python3'
pathlib.Path('fixture.json').write_text(json.dumps({'message': 'toolkit smoke'}))
# A complete one-page PDF with an embedded text stream and byte-accurate xref.
stream = b'BT /F1 18 Tf 72 720 Td (Toolkit PDF smoke) Tj ET\n'
objects = [
    b'<< /Type /Catalog /Pages 2 0 R >>',
    b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    b'<< /Length %d >>\nstream\n' % len(stream) + stream + b'endstream',
]
data = bytearray(b'%PDF-1.4\n')
offsets = [0]
for i, obj in enumerate(objects, 1):
    offsets.append(len(data))
    data.extend(b'%d 0 obj\n' % i + obj + b'\nendobj\n')
xref = len(data)
data.extend(b'xref\n0 6\n0000000000 65535 f \n')
for offset in offsets[1:]:
    data.extend(b'%010d 00000 n \n' % offset)
data.extend(b'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % xref)
pathlib.Path('fixture.pdf').write_bytes(data)
# A dependency-free wheel exercises uv pip without an index or build backend.
dist = 'toolkit_smoke_package-1.0.dist-info'
files = {
    'toolkit_smoke_package.py': 'VALUE = "offline wheel smoke"\n',
    f'{dist}/METADATA': 'Metadata-Version: 2.1\nName: toolkit-smoke-package\nVersion: 1.0\n',
    f'{dist}/WHEEL': 'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
}
files[f'{dist}/RECORD'] = ''.join(f'{name},,\n' for name in [*files, f'{dist}/RECORD'])
with zipfile.ZipFile('toolkit_smoke_package-1.0-py3-none-any.whl', 'w') as wheel:
    for name, content in files.items():
        wheel.writestr(name, content)
PY
uv --offline venv "$work/.venv"
"$work/.venv/bin/python" - <<'PY'
import importlib.util, pathlib, sys
assert sys.prefix != sys.base_prefix
assert pathlib.Path(sys._base_executable).resolve() == pathlib.Path('/usr/bin/python3').resolve()
assert importlib.util.find_spec('pip') is None
pathlib.Path(sys.prefix, 'writable').write_text('venv smoke')
PY
# No --python/system override: uv pip must discover .venv as its target.
uv --offline pip install ./toolkit_smoke_package-1.0-py3-none-any.whl
"$work/.venv/bin/python" - <<'PY'
import importlib.util, toolkit_smoke_package
assert toolkit_smoke_package.VALUE == 'offline wheel smoke'
assert importlib.util.find_spec('pip') is None
PY
jq -er '.message == "toolkit smoke"' fixture.json
rg --quiet 'toolkit smoke' fixture.json
zip -q fixture.zip fixture.json
unzip -q fixture.zip -d extracted
cmp fixture.json extracted/fixture.json
pdfinfo fixture.pdf | grep -Eq '^Pages: +1$'
pdftotext fixture.pdf extracted.txt
rg --quiet 'Toolkit PDF smoke' extracted.txt

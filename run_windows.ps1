py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = (py -c "import secrets; print(secrets.token_hex(32))")
$env:AUDIT_KEY = (py -c "import secrets; print(secrets.token_hex(32))")
py app.py

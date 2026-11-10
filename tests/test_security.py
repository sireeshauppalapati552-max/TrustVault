import os, tempfile, io, pytest
from app import app, init_db, DB_PATH, STORAGE
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("app.DB_PATH", tmp_path/"test.db")
    monkeypatch.setattr("app.STORAGE", tmp_path/"private")
    os.environ["SECRET_KEY"]="test-secret"; os.environ["AUDIT_KEY"]="test-audit-secret"
    import app as module
    module.AUDIT_KEY=b"test-audit-secret"
    module.STORAGE.mkdir()
    module.init_db()
    app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with app.test_client() as c:
        yield c
def login(c,user,pw):
    return c.post("/login",data={"username":user,"password":pw},follow_redirects=True)
def csrf(c):
    with c.session_transaction() as s: return s["_csrf"]
def test_viewer_cannot_download_unshared_document(client):
    login(client,"owner","Owner@12345")
    r=client.post("/upload",data={"_csrf":csrf(client),"title":"secret","category":"Legal",
      "file":(io.BytesIO(b"secret bytes"),"secret.txt")},content_type="multipart/form-data",follow_redirects=True)
    assert r.status_code==200
    import app as m
    with m.app.app_context():
        doc=m.db().execute("SELECT id FROM documents").fetchone()
        docid=doc["id"]
    client.post("/logout",data={"_csrf":csrf(client)})
    login(client,"viewer","Viewer@12345")
    assert client.get(f"/download/{docid}").status_code==403
    assert client.get(f"/document/{docid}").status_code==403
def test_grant_then_revoke_blocks_immediately(client):
    login(client,"owner","Owner@12345")
    client.post("/upload",data={"_csrf":csrf(client),"title":"shared","category":"HR",
      "file":(io.BytesIO(b"hello"),"a.txt")},content_type="multipart/form-data")
    import app as m
    with m.app.app_context(): did=m.db().execute("SELECT id FROM documents").fetchone()["id"]
    client.post(f"/document/{did}/grant",data={"_csrf":csrf(client),"username":"viewer","permission":"read"})
    client.post("/logout",data={"_csrf":csrf(client)})
    login(client,"viewer","Viewer@12345")
    assert client.get(f"/download/{did}").status_code==200
    client.post("/logout",data={"_csrf":csrf(client)})
    login(client,"owner","Owner@12345")
    client.post(f"/document/{did}/revoke/3",data={"_csrf":csrf(client)})
    client.post("/logout",data={"_csrf":csrf(client)})
    login(client,"viewer","Viewer@12345")
    assert client.get(f"/download/{did}").status_code==403
def test_viewer_cannot_upload(client):
    login(client,"viewer","Viewer@12345")
    assert client.get("/upload").status_code==403

def test_denied_access_is_audited(client):
    login(client,"owner","Owner@12345")
    client.post("/upload",data={"_csrf":csrf(client),"title":"private","category":"Legal",
      "file":(io.BytesIO(b"private"),"private.txt")},content_type="multipart/form-data")
    import app as m
    with m.app.app_context(): did=m.db().execute("SELECT id FROM documents").fetchone()["id"]
    client.post("/logout",data={"_csrf":csrf(client)})
    login(client,"viewer","Viewer@12345")
    response = client.get(f"/download/{did}")
    assert response.status_code == 403
    with m.app.app_context():
        event = m.db().execute("SELECT action FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        assert event["action"] == "access_denied"

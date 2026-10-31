"""Checks for Step 9 (encrypted image vault). Run from the repo root:

    python tests/smoke_step9.py

Uses a temporary database, keys, and upload folder, so your real data is untouched.
"""
import io
import os
import random
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from PIL import Image  # noqa: E402

from app import create_app  # noqa: E402

tmp = tempfile.mkdtemp()
app = create_app({
    "DB_PATH": os.path.join(tmp, "test.db"),
    "SECRETS_DIR": os.path.join(tmp, "secrets"),
    "UPLOAD_DIR": os.path.join(tmp, "uploads"),
    "MAX_CONTENT_LENGTH": 200_000,  # small limit so the size test is quick
})
client = app.test_client()
DB = app.config["DB_PATH"]
UPLOADS = app.config["UPLOAD_DIR"]
URL = "/api/vault/images"
passed = 0


def check(name, condition):
    global passed
    print(("PASS  " if condition else "FAIL  ") + name)
    if not condition:
        sys.exit(1)
    passed += 1


def make_user(name):
    client.post("/api/register", json={"username": name, "password": "a-long-test-password"})
    token = client.post("/api/login", json={"username": name, "password": "a-long-test-password"}).json["token"]
    return {"Authorization": "Bearer " + token}


def make_image(fmt="PNG", size=(64, 64)):
    rnd = random.Random(1)
    img = Image.new("RGB", size)
    img.putdata([(rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)) for _ in range(size[0] * size[1])])
    buf = io.BytesIO()
    img.save(buf, fmt)
    return buf.getvalue()


def upload(headers, data, filename="photo.png"):
    return client.post(URL, data={"file": (io.BytesIO(data), filename)},
                       headers=headers, content_type="multipart/form-data")


def stored_files():
    return sorted(os.listdir(UPLOADS)) if os.path.isdir(UPLOADS) else []


alice = make_user("alice")
bob = make_user("bob")
png = make_image("PNG")
jpg = make_image("JPEG")

# --- upload / list / download ----------------------------------------------
check("images require login", client.get(URL).status_code == 401)
r = upload(alice, png)
check("upload PNG", r.status_code == 201 and r.json["mime"] == "image/png")
img_id = r.json["id"]
check("upload JPEG", upload(alice, jpg, "pic.jpg").status_code == 201)

listing = client.get(URL, headers=alice).json["images"]
check("list shows metadata only", len(listing) == 2 and "stored_name" not in listing[0])

dl = client.get(f"{URL}/{img_id}", headers=alice)
check("download returns identical image bytes", dl.status_code == 200 and dl.data == png)
check("download is not cached", dl.headers.get("Cache-Control") == "no-store")
check("nosniff header set", dl.headers.get("X-Content-Type-Options") == "nosniff")

# --- what is really on disk -------------------------------------------------
name = sqlite3.connect(DB).execute("SELECT stored_name FROM images WHERE id=?", (img_id,)).fetchone()[0]
with open(os.path.join(UPLOADS, name), "rb") as f:
    on_disk = f.read()
check("file on disk is encrypted (no PNG header)", b"PNG" not in on_disk[:16] and on_disk != png)
check("disk size = image + 12-byte nonce + 16-byte tag", len(on_disk) == len(png) + 28)
check("stored name is random, not the original", name != "photo.png" and name.endswith(".bin"))

r2 = upload(alice, png)
name2 = sqlite3.connect(DB).execute("SELECT stored_name FROM images WHERE id=?", (r2.json["id"],)).fetchone()[0]
with open(os.path.join(UPLOADS, name2), "rb") as f:
    check("same image uploaded twice gives different ciphertext", f.read() != on_disk)

# --- validation -------------------------------------------------------------
check("text file renamed .png is rejected", upload(alice, b"just some text, not an image", "evil.png").status_code == 400)
check("HTML file renamed .jpg is rejected", upload(alice, b"<html><script>alert(1)</script></html>", "x.jpg").status_code == 400)
check("empty file rejected", upload(alice, b"", "empty.png").status_code == 400)
check("missing file field rejected",
      client.post(URL, data={}, headers=alice, content_type="multipart/form-data").status_code == 400)
check("truncated image rejected", upload(alice, png[: len(png) // 2], "cut.png").status_code == 400)

bmp_buf = io.BytesIO()
Image.new("RGB", (8, 8)).save(bmp_buf, "BMP")
check("disallowed image type (BMP) rejected", upload(alice, bmp_buf.getvalue(), "a.bmp").status_code == 400)

bomb = io.BytesIO()
Image.new("L", (6000, 6000)).save(bomb, "PNG")  # 36 megapixels, tiny file
check("oversized dimensions (decompression bomb) rejected", upload(alice, bomb.getvalue(), "big.png").status_code == 400)

too_big = upload(alice, b"0" * 300_000, "huge.png")
check("file over size limit gets 413", too_big.status_code == 413 and "error" in too_big.json)
check("rejected uploads left no files behind", len(stored_files()) == 3)

# --- ownership --------------------------------------------------------------
check("other user cannot download my image", client.get(f"{URL}/{img_id}", headers=bob).status_code == 404)
check("other user cannot delete my image", client.delete(f"{URL}/{img_id}", headers=bob).status_code == 404)
check("other user's list is empty", client.get(URL, headers=bob).json["images"] == [])
check("my image survived", client.get(f"{URL}/{img_id}", headers=alice).data == png)

# --- tampering and swapping -------------------------------------------------
path = os.path.join(UPLOADS, name)
tampered = bytearray(on_disk)
tampered[20] ^= 1
with open(path, "wb") as f:
    f.write(bytes(tampered))
check("tampered file fails integrity check", client.get(f"{URL}/{img_id}", headers=alice).status_code == 500)

ids = [row[0] for row in sqlite3.connect(DB).execute("SELECT id FROM images ORDER BY id")]
files = dict(sqlite3.connect(DB).execute("SELECT id, stored_name FROM images").fetchall())
with open(os.path.join(UPLOADS, files[ids[1]]), "rb") as f:
    other_blob = f.read()
with open(os.path.join(UPLOADS, files[ids[2]]), "wb") as f:
    f.write(other_blob)
check("file swapped between two images is rejected", client.get(f"{URL}/{ids[2]}", headers=alice).status_code == 500)

events = {row[0] for row in sqlite3.connect(DB).execute("SELECT event FROM audit_log")}
check("audit log records image events", {"image_uploaded", "image_integrity_failure"} <= events)

# --- delete -----------------------------------------------------------------
before = len(stored_files())
check("delete works", client.delete(f"{URL}/{ids[1]}", headers=alice).status_code == 200)
check("deleted image is gone", client.get(f"{URL}/{ids[1]}", headers=alice).status_code == 404)
check("encrypted file removed from disk", len(stored_files()) == before - 1)

print(f"\nAll {passed} checks passed. Step 9 is working.")

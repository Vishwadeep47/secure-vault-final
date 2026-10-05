#!/usr/bin/env python
"""Step 11 - check that face authentication can work on THIS machine.

No SecureVault feature code is touched. This script only tests the tools:

    python scripts/check_face_setup.py                      # install + models
    python scripts/check_face_setup.py --webcam             # + camera and face matching
    python scripts/check_face_setup.py --image me.jpg       # + detect a face in a photo
    python scripts/check_face_setup.py --image a.jpg --image2 b.jpg   # + compare two photos

Why OpenCV and not dlib / face_recognition?
dlib has no ready-made install for Python 3.13 on Windows and has to be compiled
(needs CMake + Visual Studio C++ tools), which often hangs or fails. OpenCV ships
its own face detector (YuNet) and face recognizer (SFace), installs with pip, and
runs on the CPU.

Privacy: webcam frames are processed in memory only. Nothing is saved to disk.
"""
import argparse
import os
import platform
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
MODELS_DIR = os.path.join(ROOT, "models")

# OpenCV's recommended cosine-similarity cut-off for "same person" (we tune it later).
COSINE_THRESHOLD = 0.363

MODELS = {
    "detector": {
        "file": "face_detection_yunet_2023mar.onnx",
        "min_bytes": 100_000,  # a Git LFS pointer file is only ~130 bytes
        "urls": [
            "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx",
            "https://huggingface.co/opencv/face_detection_yunet/resolve/main/face_detection_yunet_2023mar.onnx",
        ],
    },
    "recognizer": {
        "file": "face_recognition_sface_2021dec.onnx",
        "min_bytes": 20_000_000,  # the real file is about 37 MB
        "urls": [
            "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx",
            "https://huggingface.co/opencv/face_recognition_sface/resolve/main/face_recognition_sface_2021dec.onnx",
        ],
    },
}

results = []  # (name, ok)


def report(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'OK' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))
    return ok


def note(text):
    print(f"      {text}")


# ------------------------------------------------------------------- step 1
def check_install():
    print(f"Python {platform.python_version()} on {platform.system()} {platform.machine()}")
    try:
        import numpy as np
    except ImportError:
        report("numpy installed", False, "run: python -m pip install -r requirements.txt")
        return None
    try:
        import cv2
    except ImportError:
        report("OpenCV installed", False, "run: python -m pip install -r requirements.txt")
        return None
    report("numpy and OpenCV import", True, f"numpy {np.__version__}, OpenCV {cv2.__version__}")

    has_api = hasattr(cv2, "FaceDetectorYN") and hasattr(cv2, "FaceRecognizerSF")
    report("OpenCV has the face detector and recognizer", has_api,
           "" if has_api else "upgrade: python -m pip install --upgrade opencv-python-headless")
    return cv2 if has_api else None


# ------------------------------------------------------------------- step 2
def download(url, dest, min_bytes):
    request = urllib.request.Request(url, headers={"User-Agent": "securevault-setup-check"})
    fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(dest), suffix=".part")
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(request, timeout=60) as response:
            while True:
                chunk = response.read(1 << 16)
                if not chunk:
                    break
                out.write(chunk)
        if os.path.getsize(tmp_path) < min_bytes:
            raise ValueError("downloaded file is too small (probably a Git LFS pointer, not the model)")
        os.replace(tmp_path, dest)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def ensure_model(key):
    spec = MODELS[key]
    os.makedirs(MODELS_DIR, exist_ok=True)
    path = os.path.join(MODELS_DIR, spec["file"])

    if os.path.exists(path) and os.path.getsize(path) >= spec["min_bytes"]:
        report(f"model present: {spec['file']}", True)
        return path
    if os.path.exists(path):
        note(f"{spec['file']} exists but is too small (broken download) - fetching it again")

    for url in spec["urls"]:
        try:
            print(f"      downloading {spec['file']} ...")
            download(url, path, spec["min_bytes"])
            report(f"model downloaded: {spec['file']}", True)
            return path
        except Exception as exc:  # network, SSL, HTTP errors, bad size
            note(f"failed from {url.split('/')[2]}: {exc}")

    report(f"model available: {spec['file']}", False, "automatic download failed")
    note("Download it manually in your browser and save it into the 'models' folder:")
    for url in spec["urls"]:
        note(f"  {url}")
    note(f"Target folder: {MODELS_DIR}")
    note(f"Expected size: at least {spec['min_bytes'] // 1000} KB. A file of ~130 bytes is wrong.")
    return None


# ------------------------------------------------------------------- step 3
def load_models(cv2, detector_path, recognizer_path):
    detector = recognizer = None
    try:
        detector = cv2.FaceDetectorYN.create(detector_path, "", (320, 320), 0.8, 0.3, 5000)
        report("face detector (YuNet) loads", True)
    except cv2.error as exc:
        report("face detector (YuNet) loads", False, str(exc).strip().splitlines()[-1])
    try:
        recognizer = cv2.FaceRecognizerSF.create(recognizer_path, "")
        report("face recognizer (SFace) loads", True)
    except cv2.error as exc:
        report("face recognizer (SFace) loads", False, str(exc).strip().splitlines()[-1])
    return detector, recognizer


def detect_largest(cv2, detector, image):
    """Return the biggest face as a row [x, y, w, h, 10 landmark values, score], or None."""
    height, width = image.shape[:2]
    detector.setInputSize((width, height))
    _, faces = detector.detect(image)
    if faces is None or len(faces) == 0:
        return None
    return max(faces, key=lambda f: f[2] * f[3])


def embed(recognizer, image, face):
    aligned = recognizer.alignCrop(image, face)
    return recognizer.feature(aligned)  # shape (1, 128)


def shrink(cv2, image, max_width=1280):
    height, width = image.shape[:2]
    if width <= max_width:
        return image
    scale = max_width / width
    return cv2.resize(image, (max_width, int(height * scale)))


def analyse(cv2, detector, recognizer, image, label):
    face = detect_largest(cv2, detector, image)
    if face is None:
        report(f"face found in {label}", False, "no face detected - try better light, face the camera, move closer")
        return None
    x, y, w, h = face[:4]
    report(f"face found in {label}", True, f"{int(w)}x{int(h)} px, confidence {face[-1]:.2f}")
    feature = embed(recognizer, image, face)
    ok = feature.shape == (1, 128)
    report(f"embedding created from {label}", ok, f"shape {feature.shape}")
    return feature if ok else None


def verdict(cv2, recognizer, f1, f2, what):
    score = recognizer.match(f1, f2, cv2.FaceRecognizerSF_FR_COSINE)
    same = score >= COSINE_THRESHOLD
    report(f"{what}: similarity {score:.3f}", True,
           f"{'looks like the SAME person' if same else 'looks like DIFFERENT people'} "
           f"(threshold {COSINE_THRESHOLD})")
    return score


# --------------------------------------------------------------- optional tests
def test_images(cv2, detector, recognizer, path1, path2):
    features = []
    for label, path in (("photo 1", path1), ("photo 2", path2)):
        if not path:
            continue
        image = cv2.imread(path)
        if image is None:
            report(f"{label} can be read", False, f"cannot open {path}")
            continue
        features.append(analyse(cv2, detector, recognizer, shrink(cv2, image), label))
    if len(features) == 2 and all(f is not None for f in features):
        verdict(cv2, recognizer, features[0], features[1], "photo 1 vs photo 2")


def camera_backends(cv2):
    """Windows has two camera drivers; some laptops only give a picture on one of them."""
    if os.name == "nt":
        return [("DirectShow", cv2.CAP_DSHOW), ("Media Foundation", cv2.CAP_MSMF)]
    return [("default", cv2.CAP_ANY)]


def open_working_camera(cv2, camera_index, backends):
    """Return an open camera that gives a real picture, or None.

    A camera can "open" and still send completely black frames (closed privacy
    shutter, wrong driver, another app using it). So we check the picture itself.
    """
    for name, backend in backends:
        cap = cv2.VideoCapture(camera_index, backend)
        if not cap.isOpened():
            note(f"{name}: camera {camera_index} did not open")
            cap.release()
            continue
        brightest = 0.0
        deadline = time.time() + 4  # cameras need a moment to switch on
        while time.time() < deadline:
            ok, frame = cap.read()
            if ok and frame is not None:
                brightest = max(brightest, float(frame.mean()))
                if brightest >= 5:
                    break
            time.sleep(0.05)
        if brightest >= 5:
            note(f"{name}: working (brightness {brightest:.0f}/255)")
            return cap
        note(f"{name}: opened, but the picture is black (brightness {brightest:.0f}/255)")
        cap.release()
    return None


def test_webcam(cv2, detector, recognizer, camera_index):
    cap = open_working_camera(cv2, camera_index, camera_backends(cv2))
    if cap is None:
        report("webcam gives a picture", False, f"camera {camera_index} is not usable")
        note("Black picture? Check the physical privacy shutter or the Fn camera key.")
        note("Open the Windows Camera app: if it shows you, close it and run this again.")
        note("Close apps using the camera (Zoom, Teams, browser tabs).")
        note("Windows: Settings > Privacy & security > Camera > allow desktop apps.")
        note("Virtual cameras (OBS, DroidCam) can take index 0 - try: --camera 1")
        return
    report("webcam gives a picture", True)

    try:
        features = []
        for shot in (1, 2):
            print(f"      Look at the camera. Taking photo {shot} in 2 seconds ...")
            time.sleep(2)
            ok, frame = cap.read()
            if not ok or frame is None:
                report(f"webcam photo {shot}", False, "camera returned no image")
                return
            brightness = frame.mean()
            if brightness < 60:
                note(f"Photo {shot} is dark (brightness {brightness:.0f}/255) - add light for better results.")
            features.append(analyse(cv2, detector, recognizer, frame, f"webcam photo {shot}"))
    finally:
        cap.release()

    if all(f is not None for f in features):
        verdict(cv2, recognizer, features[0], features[1], "webcam photo 1 vs 2 (same you)")


# ------------------------------------------------------------------------ main
def main():
    parser = argparse.ArgumentParser(description="Check face authentication setup")
    parser.add_argument("--webcam", action="store_true", help="test the camera and face matching")
    parser.add_argument("--camera", type=int, default=0, help="camera index (default 0)")
    parser.add_argument("--image", help="photo to test face detection on")
    parser.add_argument("--image2", help="second photo to compare with --image")
    args = parser.parse_args()

    cv2 = check_install()
    detector = recognizer = None
    if cv2 is not None:
        detector_path = ensure_model("detector")
        recognizer_path = ensure_model("recognizer")
        if detector_path and recognizer_path:
            detector, recognizer = load_models(cv2, detector_path, recognizer_path)

    if detector is not None and recognizer is not None:
        if args.image:
            test_images(cv2, detector, recognizer, args.image, args.image2)
        if args.webcam:
            test_webcam(cv2, detector, recognizer, args.camera)

    failed = [name for name, ok in results if not ok]
    print()
    if failed:
        print(f"NOT READY - {len(failed)} problem(s):")
        for name in failed:
            print(f"  - {name}")
        sys.exit(1)
    print("READY - face detection and recognition work on this machine.")
    if not args.webcam:
        print("Tip: run again with --webcam to test your camera.")


if __name__ == "__main__":
    main()

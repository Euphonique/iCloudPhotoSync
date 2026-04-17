"""
HEIC Converter — converts HEIC/HEIF images to JPG.

Fallback chain (in order):
  1. Cross-compiled heif-convert    (installed to bin/ via spksrc cross/heif-convert)
  2. Bundled heif-convert           (legacy: per-arch under bin/heif/<arch>/)
  3. SynoCommunity imagemagick SPK  (/var/packages/imagemagick/target/bin/convert)
  4. Synology CodecPack / AME       (/var/packages/CodecPack/target/usr/bin/convert)
  5. System `convert` on PATH
  6. Pillow + pillow-heif           (only if vendored — Py 3.10+ and not default)
"""
import logging
import os
import platform
import shutil
import subprocess

LOGGER = logging.getLogger("heic_converter")

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BIN_ROOT = os.path.join(_PKG_ROOT, "bin", "heif")


def _detect_arch():
    """Map uname -m to our bin/heif/<arch>/ layout."""
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("aarch64", "arm64", "armv8", "armv8l"):
        return "aarch64"
    if m.startswith("armv7"):
        return "armv7"
    return None


def _probe_cross_compiled_heif():
    """Check for heif-convert installed by spksrc cross-compilation."""
    binary = os.path.join(_PKG_ROOT, "bin", "heif-convert")
    lib_dir = os.path.join(_PKG_ROOT, "lib")
    plugin_dir = os.path.join(lib_dir, "libheif", "plugins")
    if os.path.isfile(binary) and os.access(binary, os.X_OK):
        return {
            "cmd": "heif-convert",
            "binary": binary,
            "lib_dir": lib_dir if os.path.isdir(lib_dir) else None,
            "plugin_dir": plugin_dir if os.path.isdir(plugin_dir) else None,
            "source": "cross-compiled",
        }
    return None


def _probe_bundled_heif():
    """Check for legacy bundled per-architecture heif-convert."""
    arch = _detect_arch()
    if not arch:
        return None
    archdir = os.path.join(_BIN_ROOT, arch)
    binary = os.path.join(archdir, "heif-convert")
    lib_dir = os.path.join(archdir, "lib")
    plugin_dir = os.path.join(lib_dir, "libheif", "plugins")
    if os.path.isfile(binary) and os.access(binary, os.X_OK):
        return {
            "cmd": "heif-convert",
            "binary": binary,
            "lib_dir": lib_dir if os.path.isdir(lib_dir) else None,
            "plugin_dir": plugin_dir if os.path.isdir(plugin_dir) else None,
            "source": "bundled",
        }
    return None


def _probe_magick(path, source):
    if os.path.isfile(path) and os.access(path, os.X_OK):
        lib = os.path.join(os.path.dirname(os.path.dirname(path)), "lib")
        return {
            "cmd": "convert",
            "binary": path,
            "lib_dir": lib if os.path.isdir(lib) else None,
            "plugin_dir": None,
            "source": source,
        }
    return None


def _probe_backends():
    b = _probe_cross_compiled_heif()
    if b:
        return b
    b = _probe_bundled_heif()
    if b:
        return b
    b = _probe_magick("/var/packages/imagemagick/target/bin/convert", "synocommunity")
    if b:
        return b
    b = _probe_magick("/var/packages/CodecPack/target/usr/bin/convert", "codecpack")
    if b:
        return b
    p = shutil.which("convert")
    if p:
        return {"cmd": "convert", "binary": p, "lib_dir": None, "plugin_dir": None, "source": "system"}
    return None


_BACKEND = _probe_backends()
_PILLOW_OK = False
if not _BACKEND:
    try:
        from PIL import Image  # noqa: F401
        import pillow_heif
        pillow_heif.register_heif_opener()
        _PILLOW_OK = True
    except Exception:
        _PILLOW_OK = False

if _BACKEND:
    LOGGER.info("HEIC converter: %s (%s) at %s", _BACKEND["cmd"], _BACKEND["source"], _BACKEND["binary"])
elif _PILLOW_OK:
    LOGGER.info("HEIC converter: Pillow + pillow-heif")
else:
    LOGGER.warning("HEIC converter: no backend available — HEIC files will stay as HEIC")


def backend_info():
    """Return a dict describing the active backend, for UI/status pages."""
    if _BACKEND:
        return {
            "available": True,
            "backend": _BACKEND["cmd"],
            "source": _BACKEND["source"],
            "binary": _BACKEND["binary"],
        }
    if _PILLOW_OK:
        return {"available": True, "backend": "pillow", "source": "vendored", "binary": None}
    return {"available": False, "backend": None, "source": None, "binary": None}


def is_heic(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext in (".heic", ".heif")


def can_convert():
    return _BACKEND is not None or _PILLOW_OK


def convert_to_jpg(heic_path, jpg_path=None, quality=92):
    """Convert HEIC to JPG. Returns output path on success, None on failure."""
    if not can_convert():
        return None

    if jpg_path is None:
        jpg_path = os.path.splitext(heic_path)[0] + ".jpg"

    if _BACKEND:
        return _convert_cli(heic_path, jpg_path, quality)
    if _PILLOW_OK:
        return _convert_pillow(heic_path, jpg_path, quality)
    return None


def _convert_cli(heic_path, jpg_path, quality):
    env = os.environ.copy()
    if _BACKEND.get("lib_dir"):
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = _BACKEND["lib_dir"] + (":" + existing if existing else "")
    if _BACKEND.get("plugin_dir"):
        env["LIBHEIF_PLUGIN_PATH"] = _BACKEND["plugin_dir"]

    if _BACKEND["cmd"] == "heif-convert":
        # heif-convert syntax: heif-convert [-q N] input output
        cmd = [_BACKEND["binary"], "-q", str(quality), heic_path, jpg_path]
    else:
        # ImageMagick convert syntax: convert input -quality N output
        cmd = [_BACKEND["binary"], heic_path, "-quality", str(quality), jpg_path]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env)
        if result.returncode == 0 and os.path.isfile(jpg_path):
            try:
                os.chmod(jpg_path, 0o644)
            except OSError:
                pass
            LOGGER.info("Converted %s -> %s (%s/%s)", heic_path, jpg_path,
                        _BACKEND["cmd"], _BACKEND["source"])
            return jpg_path
        LOGGER.error("%s failed for %s: %s", _BACKEND["cmd"], heic_path, (result.stderr or "").strip())
        return None
    except subprocess.TimeoutExpired:
        LOGGER.error("%s timed out for %s", _BACKEND["cmd"], heic_path)
        return None
    except Exception as e:
        LOGGER.error("%s error for %s: %s", _BACKEND["cmd"], heic_path, e)
        return None


def _convert_pillow(heic_path, jpg_path, quality):
    try:
        from PIL import Image
        img = Image.open(heic_path)
        exif = img.info.get("exif", b"")
        if exif:
            img.save(jpg_path, "JPEG", quality=quality, exif=exif)
        else:
            img.save(jpg_path, "JPEG", quality=quality)
        try:
            os.chmod(jpg_path, 0o644)
        except OSError:
            pass
        LOGGER.info("Converted %s -> %s (Pillow)", heic_path, jpg_path)
        return jpg_path
    except Exception as e:
        LOGGER.error("Pillow conversion failed for %s: %s", heic_path, e)
        return None

#!/usr/bin/env python3
"""
Cross-platform package builder generating .deb (Ubuntu/Debian) and .rpm (RHEL/CentOS/Rocky/AlmaLinux)
packages for Zimbra Outbound Spam Monitor (zimbra-spam-monitor).
"""

import gzip
import hashlib
import io
import os
import struct
import sys
import tarfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PKG_NAME = "zimbra-spam-monitor"
PKG_VERSION = "1.2.0"
PKG_RELEASE = "1"
PKG_SUMMARY = "Zimbra Outbound Email Spam Monitor & Alert System (Telegram + Email)"
PKG_DESC = (
    "Multi-signal outbound spam detection and alerting system for Zimbra Collaboration Suite.\n"
    "- Evaluates 8 anti-spam metrics per short sliding window (default 5 minutes).\n"
    "- Correlates Zimbra Amavis Queue-ID hops and ignores old Postfix queue retries.\n"
    "- Inspects Postfix mail queue (postqueue) per sender and server-wide.\n"
    "- Sends instant alerts via Telegram Bot API and Email (Local Postfix / External SMTP).\n"
    "- Automatically locks compromised accounts (zimbraAccountStatus locked) on Critical."
)
PKG_MAINTAINER = "Zimbra Admin <179321164+0xAndyNew@users.noreply.github.com>"
PKG_LICENSE = "MIT"
BUILD_TIME = 1730000000

ROOT_DIR = Path(__file__).resolve().parent.parent


def read_lf_bytes(path: Path) -> bytes:
    """Read file and normalize line endings to Unix LF (\\n)."""
    raw = path.read_bytes()
    return raw.replace(b"\r\n", b"\n")


POSTINST_SCRIPT = b"""#!/bin/sh
set -e
mkdir -p /var/lib/zimbra-spam-monitor
touch /var/log/zimbra-spam-monitor.log
chmod 0640 /var/log/zimbra-spam-monitor.log 2>/dev/null || true
chmod 0640 /etc/zimbra-spam-monitor/config.conf 2>/dev/null || true
chmod 0644 /etc/cron.d/zimbra-spam-monitor 2>/dev/null || true
chmod 0755 /usr/bin/zimbra-spam-monitor 2>/dev/null || true

echo "======================================================================"
echo " [OK] Installed successfully: zimbra-spam-monitor v1.2.0"
echo "----------------------------------------------------------------------"
echo " -> Run the command below to open the INTERACTIVE CONTROL PANEL:"
echo "      zimbra-spam-monitor"
echo "======================================================================"
exit 0
"""

POSTRM_SCRIPT = b"""#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ] || [ "$1" = "0" ]; then
    rm -rf /var/lib/zimbra-spam-monitor
fi
if [ "$1" = "purge" ]; then
    rm -rf /etc/zimbra-spam-monitor
    rm -f /var/log/zimbra-spam-monitor.log
fi
exit 0
"""


def get_package_files():
    """Return sorted list of files and directories to package."""
    bin_bytes = read_lf_bytes(ROOT_DIR / "src" / "zimbra-spam-monitor")
    cfg_bytes = read_lf_bytes(ROOT_DIR / "config" / "config.conf")
    wl_bytes = read_lf_bytes(ROOT_DIR / "config" / "whitelist.conf")
    cron_bytes = read_lf_bytes(ROOT_DIR / "packaging" / "cron.d" / "zimbra-spam-monitor")
    logrot_bytes = read_lf_bytes(
        ROOT_DIR / "packaging" / "logrotate.d" / "zimbra-spam-monitor"
    )

    items = [
        {
            "path": "/etc/cron.d/zimbra-spam-monitor",
            "type": "file",
            "mode": 0o644,
            "is_config": True,
            "data": cron_bytes,
        },
        {
            "path": "/etc/logrotate.d/zimbra-spam-monitor",
            "type": "file",
            "mode": 0o644,
            "is_config": True,
            "data": logrot_bytes,
        },
        {
            "path": "/etc/zimbra-spam-monitor",
            "type": "dir",
            "mode": 0o755,
            "is_config": False,
            "data": b"",
        },
        {
            "path": "/etc/zimbra-spam-monitor/config.conf",
            "type": "file",
            "mode": 0o640,
            "is_config": True,
            "data": cfg_bytes,
        },
        {
            "path": "/etc/zimbra-spam-monitor/whitelist.conf",
            "type": "file",
            "mode": 0o644,
            "is_config": True,
            "data": wl_bytes,
        },
        {
            "path": "/usr/bin/zimbra-spam-monitor",
            "type": "file",
            "mode": 0o755,
            "is_config": False,
            "data": bin_bytes,
        },
        {
            "path": "/var/lib/zimbra-spam-monitor",
            "type": "dir",
            "mode": 0o755,
            "is_config": False,
            "data": b"",
        },
    ]
    return items


# ==============================================================================
# 1. DEBIAN (.DEB) PACKAGE BUILDER
# ==============================================================================
def make_tar_gz(entries) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=BUILD_TIME) as gz:
        with tarfile.open(mode="w", fileobj=gz, format=tarfile.GNU_FORMAT) as tf:
            for e in entries:
                ti = tarfile.TarInfo(name=e["name"])
                ti.mtime = BUILD_TIME
                ti.uid = 0
                ti.gid = 0
                ti.uname = "root"
                ti.gname = "root"
                if e["type"] == "dir":
                    ti.type = tarfile.DIRTYPE
                    ti.mode = e["mode"]
                    ti.size = 0
                    tf.addfile(ti)
                else:
                    ti.type = tarfile.REGTYPE
                    ti.mode = e["mode"]
                    ti.size = len(e["data"])
                    tf.addfile(ti, io.BytesIO(e["data"]))
    return buf.getvalue()


def make_ar_member(name: str, data: bytes) -> bytes:
    header = (
        f"{name:<16}"
        f"{BUILD_TIME:<12}"
        f"{0:<6}"
        f"{0:<6}"
        f"{0o100644:<8o}"
        f"{len(data):<10}"
        "`\n"
    ).encode("ascii")
    pad = b"\n" if (len(data) % 2 == 1) else b""
    return header + data + pad


def build_deb(out_path: Path):
    items = get_package_files()

    parent_dirs = [
        "./",
        "./etc/",
        "./etc/cron.d/",
        "./etc/logrotate.d/",
        "./etc/zimbra-spam-monitor/",
        "./usr/",
        "./usr/bin/",
        "./var/",
        "./var/lib/",
        "./var/lib/zimbra-spam-monitor/",
    ]
    data_entries = [{"name": d, "type": "dir", "mode": 0o755, "data": b""} for d in parent_dirs]

    md5_lines = []
    conffiles_lines = []
    total_size_bytes = 0

    for item in items:
        if item["type"] == "file":
            rel_name = "." + item["path"]
            data_entries.append(
                {
                    "name": rel_name,
                    "type": "file",
                    "mode": item["mode"],
                    "data": item["data"],
                }
            )
            md5_hex = hashlib.md5(item["data"]).hexdigest()
            md5_lines.append(f"{md5_hex}  {item['path'].lstrip('/')}\n")
            total_size_bytes += len(item["data"])
            if item["is_config"]:
                conffiles_lines.append(f"{item['path']}\n")

    data_tar_gz = make_tar_gz(data_entries)

    installed_kb = max(16, (total_size_bytes + 1023) // 1024)
    control_text = (
        f"Package: {PKG_NAME}\n"
        f"Version: {PKG_VERSION}-{PKG_RELEASE}\n"
        f"Section: admin\n"
        f"Priority: optional\n"
        f"Architecture: all\n"
        f"Depends: bash, gawk, curl, cron\n"
        f"Installed-Size: {installed_kb}\n"
        f"Maintainer: {PKG_MAINTAINER}\n"
        f"Description: {PKG_SUMMARY}\n"
        + "\n".join(f" {line}" for line in PKG_DESC.splitlines())
        + "\n"
    ).encode("utf-8")

    conffiles_bytes = "".join(conffiles_lines).encode("utf-8")
    md5sums_bytes = "".join(md5_lines).encode("utf-8")

    control_entries = [
        {"name": "./", "type": "dir", "mode": 0o755, "data": b""},
        {"name": "./control", "type": "file", "mode": 0o644, "data": control_text},
        {"name": "./conffiles", "type": "file", "mode": 0o644, "data": conffiles_bytes},
        {"name": "./md5sums", "type": "file", "mode": 0o644, "data": md5sums_bytes},
        {"name": "./postinst", "type": "file", "mode": 0o755, "data": POSTINST_SCRIPT},
        {"name": "./postrm", "type": "file", "mode": 0o755, "data": POSTRM_SCRIPT},
    ]
    control_tar_gz = make_tar_gz(control_entries)

    deb_bytes = (
        b"!<arch>\n"
        + make_ar_member("debian-binary", b"2.0\n")
        + make_ar_member("control.tar.gz", control_tar_gz)
        + make_ar_member("data.tar.gz", data_tar_gz)
    )
    out_path.write_bytes(deb_bytes)
    print(f"[OK] Built DEB package: {out_path} ({len(deb_bytes):,} bytes)")


# ==============================================================================
# 2. RPM v4 (.RPM) PACKAGE BUILDER
# ==============================================================================
RPM_NULL = 0
RPM_CHAR = 1
RPM_INT8 = 2
RPM_INT16 = 3
RPM_INT32 = 4
RPM_INT64 = 5
RPM_STRING = 6
RPM_BIN = 7
RPM_STRING_ARRAY = 8
RPM_I18NSTRING = 9


def build_cpio_newc(items) -> bytes:
    """Create SVR4 '070701' (newc) CPIO archive for RPM payload."""
    out = io.BytesIO()
    ino = 1
    for item in items:
        cpio_name = ("." + item["path"]).encode("utf-8") + b"\x00"
        if item["type"] == "dir":
            mode = 0o040000 | item["mode"]
            nlink = 2
            data = b""
        else:
            mode = 0o100000 | item["mode"]
            nlink = 1
            data = item["data"]

        namesize = len(cpio_name)
        filesize = len(data)
        hdr = (
            "070701"
            f"{ino:08X}"
            f"{mode:08X}"
            f"{0:08X}"
            f"{0:08X}"
            f"{nlink:08X}"
            f"{BUILD_TIME:08X}"
            f"{filesize:08X}"
            f"{0:08X}"
            f"{1:08X}"
            f"{0:08X}"
            f"{0:08X}"
            f"{namesize:08X}"
            f"{0:08X}"
        ).encode("ascii")
        out.write(hdr)
        out.write(cpio_name)
        rem = (110 + namesize) % 4
        if rem:
            out.write(b"\x00" * (4 - rem))

        if filesize > 0:
            out.write(data)
            rem_d = filesize % 4
            if rem_d:
                out.write(b"\x00" * (4 - rem_d))
        ino += 1

    trailer_name = b"TRAILER!!!\x00"
    t_ns = len(trailer_name)
    t_hdr = (
        "070701"
        + ("00000000" * 4)
        + "00000001"
        + ("00000000" * 6)
        + f"{t_ns:08X}"
        + "00000000"
    ).encode("ascii")
    out.write(t_hdr)
    out.write(trailer_name)
    rem = (110 + t_ns) % 4
    if rem:
        out.write(b"\x00" * (4 - rem))

    return out.getvalue()


def pack_rpm_header(tags_list, region_tag: int) -> bytes:
    """Pack RPM Header with Immutable Region Tag (63 for Main, 62 for Signature)."""
    sorted_tags = sorted(tags_list, key=lambda x: x[0])
    index_entries = []
    data_store = bytearray()

    for tag_id, dtype, val in sorted_tags:
        if dtype == RPM_INT16 and (len(data_store) % 2 != 0):
            data_store.extend(b"\x00" * (2 - (len(data_store) % 2)))
        elif dtype == RPM_INT32 and (len(data_store) % 4 != 0):
            data_store.extend(b"\x00" * (4 - (len(data_store) % 4)))
        elif dtype == RPM_INT64 and (len(data_store) % 8 != 0):
            data_store.extend(b"\x00" * (8 - (len(data_store) % 8)))

        offset = len(data_store)

        if dtype in (RPM_STRING, RPM_I18NSTRING):
            s_bytes = val.encode("utf-8") + b"\x00"
            data_store.extend(s_bytes)
            count = 1
        elif dtype == RPM_STRING_ARRAY:
            count = len(val)
            for s in val:
                data_store.extend(s.encode("utf-8") + b"\x00")
        elif dtype == RPM_BIN:
            data_store.extend(val)
            count = len(val)
        elif dtype == RPM_INT32:
            if not isinstance(val, (list, tuple)):
                val = [val]
            count = len(val)
            for v in val:
                data_store.extend(struct.pack("!I", v & 0xFFFFFFFF))
        elif dtype == RPM_INT16:
            if not isinstance(val, (list, tuple)):
                val = [val]
            count = len(val)
            for v in val:
                data_store.extend(struct.pack("!H", v & 0xFFFF))
        else:
            raise ValueError(f"Unsupported RPM type: {dtype}")

        index_entries.append((tag_id, dtype, offset, count))

    total_entries = len(index_entries) + 1
    region_offset = len(data_store)
    neg_dl = -(total_entries * 16)
    trailer_bytes = struct.pack("!iiIi", region_tag, RPM_BIN, neg_dl & 0xFFFFFFFF, 16)
    data_store.extend(trailer_bytes)

    all_index_bytes = bytearray()
    all_index_bytes.extend(struct.pack("!IIII", region_tag, RPM_BIN, region_offset, 16))
    for tag_id, dtype, offset, count in index_entries:
        all_index_bytes.extend(struct.pack("!IIII", tag_id, dtype, offset, count))

    magic_prefix = b"\x8e\xad\xe8\x01\x00\x00\x00\x00" + struct.pack(
        "!II", total_entries, len(data_store)
    )
    return magic_prefix + bytes(all_index_bytes) + bytes(data_store)


def build_rpm(out_path: Path):
    items = get_package_files()

    cpio_raw = build_cpio_newc(items)
    cpio_gz_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=cpio_gz_buf, compresslevel=9, mtime=BUILD_TIME) as gz:
        gz.write(cpio_raw)
    payload_gz = cpio_gz_buf.getvalue()

    dirnames = []
    dir_map = {}
    dirindexes = []
    basenames = []
    filesizes = []
    filemodes = []
    filerdevs = []
    filemtimes = []
    filedigests = []
    filelinktos = []
    fileflags = []
    fileusernames = []
    filegroupnames = []
    filedevices = []
    fileinodes = []
    filelangs = []

    total_reg_size = 0
    for idx, item in enumerate(items, start=1):
        p = item["path"]
        parent_dir = os.path.dirname(p).replace("\\", "/")
        if not parent_dir.endswith("/"):
            parent_dir += "/"
        bname = os.path.basename(p)

        if parent_dir not in dir_map:
            dir_map[parent_dir] = len(dirnames)
            dirnames.append(parent_dir)

        dirindexes.append(dir_map[parent_dir])
        basenames.append(bname)

        if item["type"] == "dir":
            filesizes.append(0)
            filemodes.append(0o040000 | item["mode"])
            filedigests.append("")
            fileflags.append(0)
        else:
            sz = len(item["data"])
            filesizes.append(sz)
            total_reg_size += sz
            filemodes.append(0o100000 | item["mode"])
            filedigests.append(hashlib.sha256(item["data"]).hexdigest())
            fileflags.append(17 if item["is_config"] else 0)

        filerdevs.append(0)
        filemtimes.append(BUILD_TIME)
        filelinktos.append("")
        fileusernames.append("root")
        filegroupnames.append("root")
        filedevices.append(1)
        fileinodes.append(idx)
        filelangs.append("")

    RPMLIB_FLAG = 0x0100000A
    req_names = [
        "/bin/bash",
        "/bin/sh",
        "rpmlib(CompressedFileNames)",
        "rpmlib(FileDigests)",
        "rpmlib(PayloadFilesHavePrefix)",
    ]
    req_vers = ["", "", "3.0.4-1", "4.6.0-1", "4.0-1"]
    req_flags = [0, 0, RPMLIB_FLAG, RPMLIB_FLAG, RPMLIB_FLAG]

    main_tags = [
        (100, RPM_STRING_ARRAY, ["C"]),
        (1000, RPM_STRING, PKG_NAME),
        (1001, RPM_STRING, PKG_VERSION),
        (1002, RPM_STRING, PKG_RELEASE),
        (1004, RPM_I18NSTRING, PKG_SUMMARY),
        (1005, RPM_I18NSTRING, PKG_DESC),
        (1006, RPM_INT32, BUILD_TIME),
        (1007, RPM_STRING, "zimbra-buildhost"),
        (1009, RPM_INT32, total_reg_size),
        (1014, RPM_STRING, PKG_LICENSE),
        (1016, RPM_I18NSTRING, "System Environment/Daemons"),
        (1021, RPM_STRING, "linux"),
        (1022, RPM_STRING, "noarch"),
        (1024, RPM_STRING, POSTINST_SCRIPT.decode("utf-8")),
        (1026, RPM_STRING, POSTRM_SCRIPT.decode("utf-8")),
        (1028, RPM_INT32, filesizes),
        (1030, RPM_INT16, filemodes),
        (1033, RPM_INT16, filerdevs),
        (1034, RPM_INT32, filemtimes),
        (1035, RPM_STRING_ARRAY, filedigests),
        (1036, RPM_STRING_ARRAY, filelinktos),
        (1037, RPM_INT32, fileflags),
        (1039, RPM_STRING_ARRAY, fileusernames),
        (1040, RPM_STRING_ARRAY, filegroupnames),
        (1047, RPM_STRING_ARRAY, [PKG_NAME, f"config({PKG_NAME})"]),
        (1048, RPM_INT32, req_flags),
        (1049, RPM_STRING_ARRAY, req_names),
        (1050, RPM_STRING_ARRAY, req_vers),
        (1086, RPM_STRING, "/bin/sh"),
        (1088, RPM_STRING, "/bin/sh"),
        (1095, RPM_INT32, filedevices),
        (1096, RPM_INT32, fileinodes),
        (1097, RPM_STRING_ARRAY, filelangs),
        (1112, RPM_INT32, [8, 8]),
        (1113, RPM_STRING_ARRAY, [f"{PKG_VERSION}-{PKG_RELEASE}", f"{PKG_VERSION}-{PKG_RELEASE}"]),
        (1116, RPM_INT32, dirindexes),
        (1117, RPM_STRING_ARRAY, basenames),
        (1118, RPM_STRING_ARRAY, dirnames),
        (1124, RPM_STRING, "cpio"),
        (1125, RPM_STRING, "gzip"),
        (1126, RPM_STRING, "9"),
        (5011, RPM_INT32, 8),
    ]

    main_header_bytes = pack_rpm_header(main_tags, region_tag=63)

    header_plus_payload = main_header_bytes + payload_gz
    sha1_hex = hashlib.sha1(main_header_bytes).hexdigest()
    sha256_hex = hashlib.sha256(main_header_bytes).hexdigest()
    md5_raw = hashlib.md5(header_plus_payload).digest()

    sig_tags = [
        (269, RPM_STRING, sha1_hex),
        (273, RPM_STRING, sha256_hex),
        (1000, RPM_INT32, len(header_plus_payload)),
        (1004, RPM_BIN, md5_raw),
        (1007, RPM_INT32, len(cpio_raw)),
    ]
    sig_header_bytes = pack_rpm_header(sig_tags, region_tag=62)
    sig_rem = len(sig_header_bytes) % 8
    if sig_rem:
        sig_header_bytes += b"\x00" * (8 - sig_rem)

    lead_name = f"{PKG_NAME}-{PKG_VERSION}-{PKG_RELEASE}".encode("ascii")[:65]
    lead_name = lead_name.ljust(66, b"\x00")
    lead = struct.pack(
        "!4sBBhh66shh16s",
        b"\xed\xab\xee\xdb",
        3,
        0,
        0,
        255,
        lead_name,
        1,
        5,
        b"\x00" * 16,
    )

    rpm_bytes = lead + sig_header_bytes + main_header_bytes + payload_gz
    out_path.write_bytes(rpm_bytes)
    print(f"[OK] Built RPM package: {out_path} ({len(rpm_bytes):,} bytes)")


def main():
    deb_out = ROOT_DIR / f"{PKG_NAME}_{PKG_VERSION}-{PKG_RELEASE}_all.deb"
    rpm_out = ROOT_DIR / f"{PKG_NAME}-{PKG_VERSION}-{PKG_RELEASE}.noarch.rpm"

    build_deb(deb_out)
    build_rpm(rpm_out)


if __name__ == "__main__":
    main()

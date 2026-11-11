#!/usr/bin/env python3
"""Package the verified kext with boot arguments and notices inside the bundle."""
import argparse
import hashlib
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '1.2.1'
NOTICES = {
    'LICENSE': 'GPL-2.0.txt',
    'NOTICE.md': 'NOTICE.md',
    'experimental/wpa3/rtw80211/sae/NOTICE.txt': 'SAE-NOTICE.txt',
    'experimental/wpa3/rtw80211/sae/third_party/hostap/COPYING': 'hostap-COPYING',
    'experimental/wpa3/rtw80211/sae/third_party/mbedtls/LICENSE': 'mbedtls-LICENSE',
}


def verify(path):
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None, 'Damaged release ZIP'
        names = archive.namelist()
        assert len(names) == len(set(names)), 'Duplicate archive entry'
        assert {name.split('/')[0] for name in names} == {'AirPortRTW.kext', 'BOOT-ARGS.txt'}
        assert all(not name.startswith('/') and '..' not in name.split('/') for name in names)
        assert not any(name.lower().endswith(('.zip', '.tar', '.gz')) for name in names)
        info = plistlib.loads(archive.read('AirPortRTW.kext/Contents/Info.plist'))
        assert info['CFBundleVersion'] == info['CFBundleShortVersionString'] == VERSION
        assert 'beta' not in info['CFBundleGetInfoString'].lower()
        binary_name = 'AirPortRTW.kext/Contents/MacOS/AirPortRTW'
        binary = archive.read(binary_name)
        assert struct.unpack_from('<II', binary) == (0xfeedfacf, 0x1000007), 'Expected thin x86_64 Mach-O'
        assert VERSION.encode() + b'\0' in binary
        assert b'1.2.1-beta.1' not in binary and b'1.2.1b1' not in binary
        assert archive.getinfo(binary_name).external_attr >> 16 & 0o111, 'Missing executable mode'
        for name in NOTICES.values():
            assert archive.read('AirPortRTW.kext/Contents/Resources/Notices/' + name)
        boot_args = archive.read('BOOT-ARGS.txt').decode('utf-8')
        source = (ROOT / 'src/kext/AirPortRTW.cpp').read_text()
        parsed = set(re.findall(r'PE_parse_boot_argn\("([^"]+)"', source))
        documented = set(re.findall(r'^(-rtw[a-z0-9]+)$', boot_args, re.M))
        assert parsed == documented and len(parsed) == 4, (parsed, documented)
    print('PASS: release ZIP contains only AirPortRTW.kext and BOOT-ARGS.txt; version, architecture, modes, notices and all four arguments verified')


def package(kext, output):
    assert kext.is_dir(), 'Build the kext first: make airport'
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='airport-release-') as temporary:
        stage = Path(temporary)
        bundle = stage / 'AirPortRTW.kext'
        shutil.copytree(kext, bundle, ignore=shutil.ignore_patterns('.DS_Store', '.gitkeep', '__MACOSX'))
        notices = bundle / 'Contents/Resources/Notices'
        notices.mkdir(parents=True, exist_ok=True)
        for source, name in NOTICES.items():
            shutil.copyfile(ROOT / source, notices / name)
        shutil.copyfile(ROOT / 'docs/BOOT-ARGS.txt', stage / 'BOOT-ARGS.txt')
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for file in sorted(stage.rglob('*')):
                if not file.is_file():
                    continue
                assert not file.is_symlink(), 'Unexpected bundle symlink'
                name = file.relative_to(stage).as_posix()
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                mode = 0o755 if name == 'AirPortRTW.kext/Contents/MacOS/AirPortRTW' else 0o644
                entry.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(entry, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    verify(output)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    Path(str(output) + '.sha256').write_text(digest + '  ' + output.name + '\n')
    print(digest + '  ' + output.name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kext', type=Path, default=ROOT / 'build/out/AirPortRTW.kext')
    parser.add_argument('--output', type=Path, default=ROOT / ('build/AirPortRTW-' + VERSION + '.zip'))
    parser.add_argument('--verify', type=Path, help='Verify an existing ZIP without packaging')
    args = parser.parse_args()
    if args.verify:
        verify(args.verify)
    else:
        package(args.kext, args.output)

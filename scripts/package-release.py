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
VERSION = '2.0.0'
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
        assert {name.split('/')[0] for name in names} == {'AirPortRTW.kext', 'AirBridge.kext', 'BOOT-ARGS.txt', 'rtw88-roam'}
        assert all(not name.startswith('/') and '..' not in name.split('/') for name in names)
        assert not any(name.lower().endswith(('.zip', '.tar', '.gz')) for name in names)
        assert archive.getinfo('rtw88-roam').external_attr >> 16 & 0o111
        assert b'--airbridge' in archive.read('rtw88-roam')
        info = plistlib.loads(archive.read('AirPortRTW.kext/Contents/Info.plist'))
        assert info['CFBundleVersion'] == info['CFBundleShortVersionString'] == VERSION
        assert 'beta' in info['CFBundleGetInfoString'].lower()
        binary_name = 'AirPortRTW.kext/Contents/MacOS/AirPortRTW'
        binary = archive.read(binary_name)
        assert struct.unpack_from('<II', binary) == (0xfeedfacf, 0x1000007), 'Expected thin x86_64 Mach-O'
        assert VERSION.encode() + b'\0' in binary
        assert b'2.0.0-beta.25' in binary
        assert archive.getinfo(binary_name).external_attr >> 16 & 0o111, 'Missing executable mode'
        bridge_plist = plistlib.loads(archive.read('AirBridge.kext/Contents/Info.plist'))
        assert bridge_plist['OSBundleLibraries'][info['CFBundleIdentifier']] == VERSION
        bridge_name = 'AirBridge.kext/Contents/MacOS/' + bridge_plist['CFBundleExecutable']
        bridge = archive.read(bridge_name)
        assert struct.unpack_from('<II', bridge) == (0xfeedfacf, 0x1000007)
        assert b'AirBridgeFamilyVerified' in bridge and b'AirPortRTWAirBridge' in bridge
        assert archive.getinfo(bridge_name).external_attr >> 16 & 0o111
        for name in NOTICES.values():
            assert archive.read('AirPortRTW.kext/Contents/Resources/Notices/' + name)
        boot_args = archive.read('BOOT-ARGS.txt').decode('utf-8')
        source = (ROOT / 'src/kext/AirPortRTW.cpp').read_text()
        parsed = set(re.findall(r'PE_parse_boot_argn\("([^"]+)"', source))
        documented = set(re.findall(r'^(-rtw[a-z0-9]+)$', boot_args, re.M))
        assert parsed == documented, (parsed, documented)
    print('PASS: release ZIP contains AirPortRTW.kext, AirBridge.kext and BOOT-ARGS.txt; version, architecture, modes, notices and boot arguments verified')


def package(kext, output):
    assert kext.is_dir(), 'Build the kext first: make airport'
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='airport-release-') as temporary:
        stage = Path(temporary)
        bundle = stage / 'AirPortRTW.kext'
        shutil.copytree(kext, bundle, ignore=shutil.ignore_patterns('.DS_Store', '.gitkeep', '__MACOSX'))
        shutil.copyfile(kext.parent / 'rtw88-roam', stage / 'rtw88-roam')
        bridge = stage / 'AirBridge.kext'
        shutil.copytree(kext.parent / bridge.name, bridge)
        bridge_notices = bridge / 'Contents/Resources/Notices'
        bridge_notices.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'LICENSE', bridge_notices / 'GPL-2.0.txt')
        shutil.copyfile(ROOT / 'AirBridge/NOTICE.md', bridge_notices / 'NOTICE.md')
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
                mode = 0o755 if name in ('rtw88-roam', 'AirPortRTW.kext/Contents/MacOS/AirPortRTW', 'AirBridge.kext/Contents/MacOS/AirBridge') else 0o644
                entry.external_attr = (stat.S_IFREG | mode) << 16
                archive.writestr(entry, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    verify(output)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    Path(str(output) + '.sha256').write_text(digest + '  ' + output.name + '\n')
    print(digest + '  ' + output.name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kext', type=Path, default=ROOT / 'build/out/AirPortRTW.kext')
    parser.add_argument('--output', type=Path, default=ROOT / ('build/AirPortRTW-2.0.0-beta.25.zip'))
    parser.add_argument('--verify', type=Path, help='Verify an existing ZIP without packaging')
    args = parser.parse_args()
    if args.verify:
        verify(args.verify)
    else:
        package(args.kext, args.output)

#!/usr/bin/env python3
"""Build and test the isolated SAE backend; never build or load a kext."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
SAE = ROOT / 'rtw80211/sae'

def run(*args):
    subprocess.run([str(a) for a in args], check=True)

run('python3', ROOT / 'validate_provenance.py')
cc = shlex.split(os.environ.get('CC', 'cc'))
flags = ['-std=gnu11', '-O2', '-include', str(SAE / 'namespace.h'),
         '-DMBEDTLS_CONFIG_FILE="rtw_sae_mbedtls_config.h"']
for directory in ['compat', 'third_party/hostap/src', 'third_party/hostap/src/utils',
                  'third_party/hostap/src/common', 'third_party/mbedtls/include',
                  'third_party/mbedtls/library', '.']:
    flags += ['-I', str(SAE / directory)]
sanitize = os.environ.get('SAE_HOST_SANITIZE', '0') == '1'
sanitizers = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if sanitize else []
sources = [SAE / 'third_party/hostap/src/common' / (s + '.c') for s in ['sae', 'dragonfly']]
sources += [SAE / (s + '.c') for s in ['rtw_sae', 'rtw_sae_hostap', 'rtw_sae_wpabuf', 'rtw_sae_crypto']]
sources += [SAE / 'third_party/mbedtls/library' / (s + '.c') for s in
            ['bignum', 'bignum_core', 'ecp', 'ecp_curves', 'constant_time', 'platform_util']]
with tempfile.TemporaryDirectory(prefix='airportrtw-sae-') as directory:
    out = Path(directory)
    objects = []
    for source in sources:
        obj = out / (source.stem + '.o')
        run(*cc, *flags, *sanitizers, '-c', source, '-o', obj)
        objects.append(obj)
    archive = out / 'librtw_sae.a'
    run('ar', 'rcs', archive, *objects)
    # GNU and Apple nm differ in undefined-symbol flags; inspect each defined
    # global by its type instead. Do not permit generic hostap/mbedtls exports.
    output = subprocess.check_output(['nm', '-g', str(archive)], text=True)
    defined = [line.split()[-1] for line in output.splitlines()
               if len(line.split()) == 3 and line.split()[-2].upper() in ('T', 'D', 'B', 'R', 'S', 'C', 'W', 'V')]
    assert defined, 'empty SAE archive'
    def private_symbol(symbol):
        # Apple Clang emits this ASan registration sentinel in each object.
        if sanitize and symbol == '____asan_globals_registered':
            return True
        # GCC ASan adds a companion global for each instrumented datum.
        if sanitize and symbol.startswith('__odr_asan.'):
            symbol = symbol[len('__odr_asan.'):]
        return symbol.lstrip('_').startswith(('airport_sae_', 'rtw_sae_'))
    unexpected = [s for s in defined if not private_symbol(s)]
    assert not unexpected, unexpected
    for name in ['sae_crypto_test', 'sae_exchange_test']:
        binary = out / name
        run(*cc, '-std=c11', '-Wall', '-Wextra', '-Werror', *sanitizers,
            ROOT / 'tests' / (name + '.c'), archive, '-o', binary)
        run(binary)
        print('PASS:', name, flush=True)
    binary = out / 'wpa3_session_test'
    cxx = shlex.split(os.environ.get('CXX', 'c++'))
    crypto = out / 'RTW88WPA3Crypto.o'
    crypto_source = ROOT.parents[1] / 'src/kext/RTW88WPA3Crypto.cpp'
    run(*cxx, '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation',
        *sanitizers, '-c', crypto_source, '-o', crypto)
    run(*cxx, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation', *sanitizers,
        ROOT.parents[1] / 'tests/wpa3_session_test.cpp', crypto, archive, '-o', binary)
    run(binary)
    menu = out / 'wpa3_menu_test'
    run(*cxx, '-std=c++17', '-Wall', '-Wextra', '-Werror', *sanitizers,
        ROOT.parents[1] / 'tests/wpa3_menu_test.cpp', '-o', menu)
    run(menu)
    aes_test = out / 'wpa3_aes_test'
    run(*cxx, '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', *sanitizers,
        ROOT.parents[1] / 'tests/wpa3_aes_test.cpp', archive, '-o', aes_test)
    run(aes_test)
    if os.environ.get('SAE_BENCHMARK', '0') == '1':
        benchmark = out / 'wpa3_ccmp_bench'
        run(*cxx, '-std=c++17', '-O2', *sanitizers,
            ROOT.parents[1] / 'tests/wpa3_ccmp_bench.cpp', crypto, archive, '-o', benchmark)
        run(benchmark)
        reference = out / 'wpa3_ccmp_reference_bench'
        reference_crypto = out / 'RTW88WPA3ReferenceCrypto.o'
        run(*cxx, '-std=c++17', '-O2', '-DRTW_WPA3_REFERENCE_AES=1', *sanitizers,
            '-c', crypto_source, '-o', reference_crypto)
        run(*cxx, '-std=c++17', '-O2', *sanitizers,
            ROOT.parents[1] / 'tests/wpa3_ccmp_bench.cpp', reference_crypto, archive, '-o', reference)
        print('Reference bulk AES (Beta 2):', flush=True)
        run(reference)
print('PASS: vendor provenance and private symbol isolation')

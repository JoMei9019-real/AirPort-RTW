#!/usr/bin/env python3
"""Fail CI if the compiled x86_64 reentrant IOCTL entry frames grow too large.

Counts local allocation AND saved-register pushes before the first call/branch
or return. This is a per-entry frame budget, not a whole-call-chain/recursion
proof. Unknown stack adjustments fail closed instead of silently counting zero.
"""
import re
import subprocess
import sys

BUDGETS = {'10AirPortRTW17apple80211Request': 256,
           '10AirPortRTW25handleRequestCOUNTRY_CODE': 256}

def frame_bytes(instructions):
    total = 0
    seen = False
    for instruction in instructions:
        instruction = instruction.split('##', 1)[0].strip()
        if not instruction:
            continue
        seen = True
        if re.match(r'(call\w*|j\w+|ret\w*)\b', instruction):
            return total
        if re.match(r'pushq\b', instruction):
            total += 8
        elif re.match(r'subq\b.*%rsp', instruction):
            match = re.fullmatch(r'subq\s+\$(0x[0-9a-fA-F]+|[0-9]+),\s*%rsp', instruction)
            assert match, 'Unknown stack allocation: ' + instruction
            value = match.group(1)
            total += int(value, 16 if value.startswith('0x') else 10)
        elif re.search(r',\s*%rsp\b', instruction):
            raise AssertionError('Unknown stack adjustment: ' + instruction)
        elif re.match(r'(push|pop|enter|leave)\w*\b', instruction):
            raise AssertionError('Unknown stack operation: ' + instruction)
    assert seen, 'Empty disassembly'
    raise AssertionError('No call/branch/return boundary in prologue')

def self_test():
    assert frame_bytes(['pushq %rbp', 'movq %rsp, %rbp', 'pushq %r15',
                        'subq $0x80, %rsp', 'callq 0x100']) == 144
    assert frame_bytes(['subq $32,%rsp', 'jmp 0x100']) == 32
    assert frame_bytes(['retq']) == 0
    assert frame_bytes(['subq $0x1000, %rsp', 'callq 0x100']) > 256
    for unknown in ('subq %rax, %rsp', 'andq $-16, %rsp', 'enter $32, $0'):
        try:
            frame_bytes([unknown, 'callq 0x100'])
        except AssertionError:
            pass
        else:
            raise AssertionError('Accepted unknown stack allocation: ' + unknown)
    print('PASS: stack-budget parser (saved registers, hex/decimal, oversize, unknown adjustment)')

def check(binary):
    symbols = subprocess.check_output(['xcrun', 'nm', '-n', binary], text=True)
    assembly = subprocess.check_output(['xcrun', 'otool', '-tvV', binary], text=True)
    for fragment, budget in BUDGETS.items():
        matches = [line.split()[-1] for line in symbols.splitlines()
                   if fragment in line and re.match(r'^[0-9a-fA-F]+\s+[tT]\s+', line)]
        assert len(matches) == 1, f'Expected one compiled symbol for {fragment}: {matches}'
        symbol = matches[0]
        label = re.search(r'^' + re.escape(symbol) + r':\s*$', assembly, re.M)
        assert label, 'Missing disassembly label: ' + symbol
        body = assembly[label.end():].lstrip('\n')
        next_label = re.search(r'^\S[^\n]*:\s*$', body, re.M)
        if next_label:
            body = body[:next_label.start()]
        instructions = [match.group(1) for line in body.splitlines()
                        if (match := re.match(r'^\s*[0-9a-fA-F]+\s+(.+)$', line))]
        size = frame_bytes(instructions)
        print(f'{symbol}: {size} bytes including saved registers; budget {budget}')
        assert size <= budget, f'Kernel stack budget exceeded: {size} > {budget}'
    print('PASS: compiled x86_64 IOCTL entry stack budgets')

if __name__ == '__main__':
    self_test()
    if len(sys.argv) != 2:
        raise SystemExit('Usage: check_stack_budget.py --self-test | KEXT_BINARY')
    if sys.argv[1] != '--self-test':
        check(sys.argv[1])

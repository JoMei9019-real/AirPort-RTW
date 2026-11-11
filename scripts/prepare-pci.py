#!/usr/bin/env python3
"""Apply the macOS TX producer lock fix to the pinned PCI translation unit.

The dependency checkout stays unchanged. Fail closed if the reviewed function
changes; do not silently compile an unprotected upstream version.
"""
from pathlib import Path
import argparse
import hashlib

# d029a677c49266fad86750714eb5612becd134d3, pci.c
SOURCE_SHA256 = '15b3a8225f4b0648c4587b4c8f3f1146a0110a5f47295759306bfde9e1335e20'


def prepare(source):
    if hashlib.sha256(source.encode()).hexdigest() != SOURCE_SHA256:
        raise ValueError('PCI source differs from the reviewed pinned revision')
    start = source.index('static int rtw_pci_tx_write_data(')
    end = source.index('\nstatic int rtw_pci_write_data_rsvd_page', start)
    function = source[start:end]
    lock = '\tspin_lock_bh(&rtwpci->irq_lock);\n'
    assert function.count(lock) == 1
    function = function.replace(lock + '\n', '', 1)
    function = function.replace('\tring = &rtwpci->tx_rings[queue];', '''\t/* macOS has independent data, scan-null and management producers.
\t * Protect slot selection, descriptor fill and queue publication together.
\t * This port's irq_lock is a sleepable IORecursiveLock, including while
\t * mapping DMA; it is not a native Linux spinlock. Reclamation/doorbells
\t * use the same lock and cannot observe a partially published slot. */
\tspin_lock_bh(&rtwpci->irq_lock);
\tring = &rtwpci->tx_rings[queue];''', 1)
    function = function.replace('''\telse if (!avail_desc(ring->r.wp, ring->r.rp, ring->r.len))
\t\treturn -ENOSPC;''', '''\telse if (!avail_desc(ring->r.wp, ring->r.rp, ring->r.len)) {
\t\tspin_unlock_bh(&rtwpci->irq_lock);
\t\treturn -ENOSPC;
\t}''', 1)
    function = function.replace('''\tif (dma_mapping_error(&rtwpci->pdev->dev, dma))
\t\treturn -EBUSY;''', '''\tif (dma_mapping_error(&rtwpci->pdev->dev, dma)) {
\t\tspin_unlock_bh(&rtwpci->irq_lock);
\t\treturn -EBUSY;
\t}''', 1)
    assert function.index(lock) < function.index('avail_desc(') < function.index('get_tx_buffer_desc(')
    assert function.count('spin_unlock_bh(&rtwpci->irq_lock);') == 3
    return source[:start] + function + source[end:]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = prepare(args.source.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(result)

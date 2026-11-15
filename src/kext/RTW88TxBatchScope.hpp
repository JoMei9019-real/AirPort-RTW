/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once
/* No timer or packet ownership escapes this scope. Nested callers must not
 * finish an existing batch owned by their caller. */
template<class Backend> class RTW88TxBatchScope {
    Backend *backend;
    bool active;
public:
    explicit RTW88TxBatchScope(Backend *p) : backend(p), active(p && p->beginTxBatch()) {}
    ~RTW88TxBatchScope() { if (active) backend->endTxBatch(); }
    RTW88TxBatchScope(const RTW88TxBatchScope &) = delete;
    RTW88TxBatchScope &operator=(const RTW88TxBatchScope &) = delete;
};

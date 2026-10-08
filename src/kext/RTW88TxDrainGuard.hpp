/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#pragma once

// A native output callback can re-enter the driver synchronously. Keep the
// original drain as the sole queue owner; a later timer handles queued work.
class RTW88TxDrainGuard {
    bool *_active;
public:
    explicit RTW88TxDrainGuard(bool *active) : _active(nullptr) {
        bool expected = false;
        if (__atomic_compare_exchange_n(active, &expected, true, false,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            _active = active;
    }
    ~RTW88TxDrainGuard() {
        if (_active) __atomic_store_n(_active, false, __ATOMIC_RELEASE);
    }
    bool acquired() const { return _active != nullptr; }
    RTW88TxDrainGuard(const RTW88TxDrainGuard &) = delete;
    RTW88TxDrainGuard &operator=(const RTW88TxDrainGuard &) = delete;
};

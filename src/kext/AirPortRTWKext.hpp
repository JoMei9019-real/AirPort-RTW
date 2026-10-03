/* Modified by X1REN41L on 2026-10-02 for AirPortRTW 1.0.0; see the repository NOTICE.md. */
/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 * AirPortRTWKext.hpp — top-level IOService provider matching
 */
#pragma once

#include <IOKit/IOService.h>

class AirPortRTWKext : public IOService {
    OSDeclareDefaultStructors(AirPortRTWKext)

public:
    bool init(OSDictionary *props) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;

    IOService *probe(IOService *provider, SInt32 *score) override;
};

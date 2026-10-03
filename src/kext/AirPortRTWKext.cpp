/* Modified by X1REN41L on 2026-10-02 for AirPortRTW 1.0.0; see the repository NOTICE.md. */
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// AirPortRTWKext.cpp — top-level IOService, delegates to PCI or USB device classes

#include "AirPortRTWKext.hpp"
#include <IOKit/IOLib.h>

#define super IOService
OSDefineMetaClassAndStructors(AirPortRTWKext, IOService)

bool AirPortRTWKext::init(OSDictionary *props)
{
    IOLog("rtw88: AirPortRTWKext::init\n");
    return super::init(props);
}

IOService *AirPortRTWKext::probe(IOService *provider, SInt32 *score)
{
    IOLog("rtw88: AirPortRTWKext::probe\n");
    return super::probe(provider, score);
}

bool AirPortRTWKext::start(IOService *provider)
{
    IOLog("rtw88: AirPortRTWKext::start\n");
    if (!super::start(provider)) return false;
    registerService();
    return true;
}

void AirPortRTWKext::stop(IOService *provider)
{
    IOLog("rtw88: AirPortRTWKext::stop\n");
    super::stop(provider);
}

void AirPortRTWKext::free()
{
    super::free();
}

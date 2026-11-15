#!/usr/bin/env python3
"""Exercise the production private-MAC handler and its Legacy wire layout."""

import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

root = Path(__file__).resolve().parents[1]
controller = (root / "src/kext/AirPortRTW.cpp").read_text()
backend = (root / "src/kext/RTW88IEEE80211.cpp").read_text()


def function(source, start, end):
    return source[source.index(start):source.index(end, source.index(start))]


native = function(controller, "SInt32 AirPortRTW::apple80211Request", "void AirPortRTW::logGetResult")
assert "handleStationMACRequest(isSet, request_number, interface, data)" in native
assert "request_number == RTW88StationMACWire::SetAddressSelector" in native
bsd = function(controller, "SInt32 AirPortRTW::apple80211_ioctl(", "SInt32 AirPortRTW::apple80211_ioctl_set")
assert bsd.index("len != sizeof(RTW88StationMACWire::SetAddress) || !reqData") < bsd.index("const bool scanBridge")
assert "privateMACBridge" not in controller
assert "station MAC updated to" not in controller

fixture = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include "RTW88AssocWire.hpp"
#include "RTW88StationMACWire.hpp"

using SInt32 = int32_t;
using IOReturn = int32_t;
constexpr int APPLE80211_VERSION = 1, APPLE80211_IOC_PRIVATE_MAC = 238;
constexpr int ETH_ALEN = 6;
constexpr int kIOReturnSuccess = 0, kIOReturnNotReady = -1;
constexpr int kIOReturnUnsupported = -2, kIOReturnBadArgument = -3;
constexpr int kIOReturnBusy = -4, kIOReturnError = -5;
constexpr bool kOSBooleanTrue = true, kOSBooleanFalse = false;
constexpr const char *kIOMACAddress = "IOMACAddress";
namespace RTW88IOCTLGuard { constexpr int DarwinUnsupported = 102; }
namespace RTW88Roaming {
bool unicast(const uint8_t *mac) {
    return (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) && !(mac[0] & 1);
}
}
struct OSObject {};
struct WorkLoop {
    bool gated = false;
    bool inGate() const { return gated; }
    using Action = IOReturn (*)(OSObject *, void *, void *, void *, void *);
    IOReturn runAction(Action action, OSObject *owner, void *data) {
        assert(!gated);
        gated = true;
        const IOReturn result = action(owner, data, nullptr, nullptr, nullptr);
        gated = false;
        return result;
    }
};
struct IOEthernetAddress { uint8_t bytes[6]; };
struct IO80211Interface {
    uint8_t address[6] = {0x10, 1, 2, 3, 4, 5};
    int stackError = 0;
    unsigned propertyWrites = 0;
    IO80211Interface *getIfnet() { return this; }
    void setProperty(const char *, void *data, size_t len) {
        assert(len == 6 && memcmp(data, address, len) == 0);
        ++propertyWrites;
    }
};
using ifnet_t = IO80211Interface *;
int ifnet_lladdr_copy_bytes(ifnet_t net, void *address, size_t len) {
    memcpy(address, net->address, len);
    return 0;
}
int ifnet_set_lladdr(ifnet_t net, const void *address, size_t len) {
    if (net->stackError) return net->stackError;
    memcpy(net->address, address, len);
    return 0;
}

enum State { RTW88_STATE_IDLE, RTW88_STATE_SCANNING, RTW88_STATE_HANDSHAKING };
struct Wiphy { uint8_t perm_addr[6] = {0x10, 1, 2, 3, 4, 5}; };
struct Hardware { Wiphy *wiphy; int result = 0; unsigned writes = 0; };
int rtw88_set_station_mac(Hardware *hw, void *, const uint8_t *) {
    if (hw->result) return hw->result;
    ++hw->writes;
    return 0;
}
struct RTW88IEEE80211 {
    Hardware *_hw = nullptr;
    void *_vif = this;
    uint8_t _macAddr[6] = {0x10, 1, 2, 3, 4, 5};
    State _state = RTW88_STATE_IDLE;
    bool _powered = true, _associatedVisible = false;
    unsigned _manualScanChannelCount = 0;
    bool _roamScanWorkerPending = false, _deferredConnectPending = false;
    struct { unsigned phase = 0; } _roamSwitch;
    bool _awdlOffChannel = false;

    void getMACAddress(uint8_t *mac) { memcpy(mac, _macAddr, sizeof(_macAddr)); }
    bool getPermanentMACAddress(uint8_t *mac) const;
    IOReturn setMACAddress(const uint8_t *mac);
};
struct AirPortRTW : OSObject {
    RTW88IEEE80211 *_ieee80211;
    WorkLoop *_workLoop;
    IO80211Interface *_netif;
    bool allowHardware = true;
    bool _assocOwnsStationMAC = false;
    uint32_t _privateMacFlags = 0, _privateMacTimeout = 0;
    uint32_t _privateMacGetCount = 0, _privateMacSetCount = 0;

    bool roamingActionsAllowed() const { return allowHardware; }
    void setProperty(const char *, bool) {}
    void setProperty(const char *, uint64_t, int) {}
    int errnoFromReturn(int result) {
        switch (result) {
        case kIOReturnBadArgument: return EINVAL;
        case kIOReturnBusy: return EBUSY;
        case kIOReturnNotReady: return ENXIO;
        default: return EIO;
        }
    }
    IOReturn setHardwareAddress(const IOEthernetAddress *addr);
    IOReturn setStationMAC(const uint8_t *address, bool updateBSD);
    bool matchesJoinStationAddress(const RTW88AssocWire::StationAddress &station);
    IOReturn prepareJoinStationAddress(const RTW88AssocWire::StationAddress &station);
    SInt32 handleStationMACRequest(bool isSet, int selector, IO80211Interface *, void *);
};
'''

fixture += function(controller, "IOReturn AirPortRTW::setHardwareAddress",
                    "IOReturn AirPortRTW::getHardwareAddressForInterface")
fixture += function(controller, "SInt32 AirPortRTW::handleStationMACRequest",
                    "SInt32 AirPortRTW::apple80211_ioctl(")
fixture += function(backend, "bool RTW88IEEE80211::getPermanentMACAddress",
                    "bool RTW88IEEE80211::getRadioTelemetry")
fixture += function(backend, "IOReturn RTW88IEEE80211::setMACAddress",
                    "IOReturn RTW88IEEE80211::copyScanBSS")

fixture += r'''
int main() {
    using namespace RTW88StationMACWire;
    Wiphy wiphy;
    Hardware hardware{&wiphy};
    RTW88IEEE80211 driver{};
    driver._hw = &hardware;
    WorkLoop loop;
    IO80211Interface net, other;
    AirPortRTW controller;
    controller._ieee80211 = &driver;
    controller._workLoop = &loop;
    controller._netif = &net;

    auto get = [&](PrivateMAC &data) {
        return controller.handleStationMACRequest(false, APPLE80211_IOC_PRIVATE_MAC, &net, &data);
    };
    auto set = [&](PrivateMAC &data) {
        return controller.handleStationMACRequest(true, APPLE80211_IOC_PRIVATE_MAC, &net, &data);
    };
    struct {
        PrivateMAC value;
        uint32_t canary;
    } packet = {{}, 0x12345678};
    auto &data = packet.value;
    const uint8_t fixed[6] = {0x02, 0x19, 0x57, 0x38, 0x46, 0x29};
    const uint8_t rotated[6] = {0x06, 0x55, 0x64, 0x73, 0x82, 0x91};
    assert(get(data) == 0 && !data.enabled && !data.flags && !data.timeoutSeconds);
    assert(!memcmp(data.address, wiphy.perm_addr, 6));
    assert(packet.canary == 0x12345678);
    assert(controller.handleStationMACRequest(false, APPLE80211_IOC_PRIVATE_MAC,
                                             &other, &data) == RTW88IOCTLGuard::DarwinUnsupported);

    const uint8_t raw[28] = {1, 0, 0, 0, 1, 0, 0, 0, 0x12, 0, 0, 0,
                             0, 0, 0, 0, 0x02, 0x19, 0x57, 0x38, 0x46, 0x29};
    memcpy(&data, raw, sizeof(data));
    assert(set(data) == 0 && hardware.writes == 1);
    assert(!memcmp(net.address, fixed, 6) && net.propertyWrites == 1);
    assert(get(data) == 0 && data.flags == 0x12 && data.enabled && !data.timeoutSeconds);

    driver._state = RTW88_STATE_HANDSHAKING;
    assert(set(data) == 0 && hardware.writes == 1);
    memcpy(data.address, rotated, 6);
    data.timeoutSeconds = 3600;
    assert(set(data) == EBUSY && hardware.writes == 1);
    driver._state = RTW88_STATE_SCANNING;
    assert(set(data) == EBUSY);
    driver._state = RTW88_STATE_IDLE;
    driver._manualScanChannelCount = 1;
    assert(set(data) == EBUSY);
    driver._manualScanChannelCount = 0;
    driver._deferredConnectPending = true;
    assert(set(data) == EBUSY);
    driver._deferredConnectPending = false;
    driver._roamSwitch.phase = 1;
    assert(set(data) == EBUSY);
    driver._roamSwitch.phase = 0;
    controller.allowHardware = false;
    assert(set(data) == ENXIO);
    controller.allowHardware = true;
    hardware.result = -EBUSY;
    assert(set(data) == EBUSY && hardware.writes == 1);
    hardware.result = 0;
    net.stackError = ENXIO;
    assert(set(data) == EIO && hardware.writes == 3);
    assert(!memcmp(driver._macAddr, fixed, 6) && !memcmp(net.address, fixed, 6));
    net.stackError = 0;
    assert(set(data) == 0 && hardware.writes == 4);
    assert(get(data) == 0 && data.timeoutSeconds == 3600 && data.enabled);
    assert(!memcmp(data.address, rotated, 6) && !memcmp(net.address, rotated, 6));
    data.address[0] = 1;
    assert(set(data) == EINVAL && hardware.writes == 4);
    data.version = 2;
    assert(set(data) == EINVAL);
    assert(get(data) == 0 && data.version == APPLE80211_VERSION);
    data.enabled = 0;
    assert(set(data) == 0 && get(data) == 0 && !data.enabled && !data.timeoutSeconds);
    assert(!memcmp(net.address, wiphy.perm_addr, 6));

    IOEthernetAddress ethernet;
    memcpy(ethernet.bytes, fixed, 6);
    assert(controller.setHardwareAddress(&ethernet) == 0);
    // IOEthernetInterface owns the BSD update on the Ethernet callback.
    assert(!memcmp(net.address, wiphy.perm_addr, 6));
    assert(get(data) == 0 && data.enabled && !data.flags && !data.timeoutSeconds);
    HardwareAddress permanent = {};
    assert(controller.handleStationMACRequest(false, HardwareAddressSelector,
                                             &net, &permanent) == 0);
    assert(permanent.version == 1 && !memcmp(permanent.address, wiphy.perm_addr, 6));
    assert(controller.handleStationMACRequest(true, HardwareAddressSelector,
                                             &net, &permanent) == RTW88IOCTLGuard::DarwinUnsupported);

    SetAddress requested = {{0x06, 0x55, 0x64, 0x73, 0x82, 0x91}};
    const auto setAddress = [&](IO80211Interface &interface, bool isSet = true) {
        return controller.handleStationMACRequest(isSet, SetAddressSelector, &interface, &requested);
    };
    const unsigned writes = hardware.writes;
    assert(setAddress(net, false) == RTW88IOCTLGuard::DarwinUnsupported);
    assert(setAddress(other) == RTW88IOCTLGuard::DarwinUnsupported);
    driver._state = RTW88_STATE_HANDSHAKING;
    assert(setAddress(net) == EBUSY && hardware.writes == writes);
    driver._state = RTW88_STATE_IDLE;
    requested.address[0] = 0x07;
    assert(setAddress(net) == EINVAL && hardware.writes == writes);
    requested.address[0] = rotated[0];
    assert(setAddress(net) == 0 && hardware.writes == writes + 1);
    assert(!memcmp(driver._macAddr, rotated, 6) && !memcmp(net.address, rotated, 6));
    assert(setAddress(net) == 0 && hardware.writes == writes + 1);
    memcpy(requested.address, permanent.address, 6);
    assert(setAddress(net) == 0 && hardware.writes == writes + 2);
    assert(!memcmp(net.address, wiphy.perm_addr, 6));
    assert(controller._privateMacGetCount && controller._privateMacSetCount);
    assert(packet.canary == 0x12345678);

    using Address = RTW88AssocWire::StationAddress;
    uint8_t wire[908] = {};
    Address station;
    wire[0x1d5] = 0x40; // A separate 25G342 flag, not the address presence bit.
    assert(!RTW88AssocWire::decodeTahoeStationAddress(wire, 900, station));
    memcpy(wire + 0x200, fixed, 6);
    assert(RTW88AssocWire::decodeTahoeStationAddress(wire, sizeof(wire), station));
    assert(station.mode == Address::Mode::Default);
    wire[0x1d4] = 0x08;
    wire[0x200] = 3;
    assert(!RTW88AssocWire::decodeTahoeStationAddress(wire, sizeof(wire), station));
    wire[0x200] = fixed[0];
    assert(RTW88AssocWire::decodeTahoeStationAddress(wire, sizeof(wire), station));
    assert(station.mode == Address::Mode::Private && !memcmp(station.bytes, fixed, 6));
    assert(!controller.matchesJoinStationAddress(station));
    net.stackError = ENXIO;
    assert(controller.prepareJoinStationAddress(station) == kIOReturnError);
    assert(!controller._assocOwnsStationMAC && !memcmp(net.address, wiphy.perm_addr, 6));
    net.stackError = 0;
    loop.gated = true;
    assert(controller.prepareJoinStationAddress(station) == 0);
    loop.gated = false;
    assert(controller.matchesJoinStationAddress(station) && controller._assocOwnsStationMAC);
    assert(!memcmp(driver._macAddr, fixed, 6) && !memcmp(net.address, fixed, 6));
    Address absent{Address::Mode::Default,{}};
    assert(!controller.matchesJoinStationAddress(absent));
    assert(controller.prepareJoinStationAddress(absent) == 0 && !controller._assocOwnsStationMAC);
    assert(!memcmp(net.address, wiphy.perm_addr, 6));
    assert(controller.prepareJoinStationAddress(station) == 0 && controller._assocOwnsStationMAC);
    memcpy(requested.address, fixed, 6);
    assert(setAddress(net) == 0 && !controller._assocOwnsStationMAC);
    assert(controller.prepareJoinStationAddress(absent) == 0 && !memcmp(net.address, fixed, 6));
}
'''

with TemporaryDirectory() as folder:
    source = Path(folder) / "station_mac.cpp"
    binary = Path(folder) / "station_mac"
    source.write_text(fixture)
    subprocess.run([os.environ.get("CXX", "c++"), "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    "-I", str(root / "src/kext"), str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)

print("PASS: Legacy private-MAC offsets, six-byte SET_MAC_ADDRESS, station-only routing, address replays, active-state guards, "
      "BSD rollback, Off and immutable hardware address")

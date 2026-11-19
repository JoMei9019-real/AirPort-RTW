# AirPortRTW 2.0.0 Beta 20

Beta 20 tests native AWDL transmit on x86_64 IO80211FamilyLegacy 1200.12.2b1.
AirPortBrcmNIC uses the virtual interface’s peer-queue dequeue after the family
moves packets from the BSD send queue. The driver now requests bounded data
batches with separate multicast and traffic-class budgets. It retains the BSD
dequeue as a timer fallback and recognizes the AWDL interface on the direct
controller output path. Queue acceptance and RF transmission are separate events.

The optional action tap keeps the Beta 19 Service Response/ARPA filter.
The default receive path updates the local peer table. The SDK-only peer
presence/absence methods have no matching exports in this Legacy build.

## Hardware check

Keep the same boot arguments as the Beta 19 test. Open Finder AirDrop and the
iPhone share sheet. Record the following commands before and after discovery
and three pings. The IPv6 multicast ping can reply locally.

```sh
ioreg -r -c AirPortRTW -l | grep -E '"(DriverBuild|AWDL_TX_(PEER_(REQUESTS|PACKETS|CALLBACK_PACKETS|LAST_MASK)|DIRECT_(ACCEPTED|DROPPED)|IFNET_(PACKETS|LAST_RESULT)|ACTUAL_DEQUEUED|CONTROLLER_ENQUEUE_(SUCCESS|FAILURE)|ATTEMPTS)|AWDL_LOCAL_AIRDROP_SERVICE_READY)"'
/sbin/ping6 -n -c 3 'ff02::1%awdl0'
```

Compare the counter deltas. Check whether the iPhone appears in Finder and
whether the Mac appears on the iPhone. A transfer in each direction is the
end-to-end check.

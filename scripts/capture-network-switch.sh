#!/bin/bash
# Read-only macOS switch capture. Does not alter Wi-Fi, DHCP or saved networks.
set -u

if [ "${1:-}" = "--help" ]; then
    echo "Usage: /bin/bash $0 [Wi-Fi interface, e.g. en0]"
    echo "Press Return before switching in the Wi-Fi menu, then again when the test ends."
    echo "Includes a bounded DHCP/ARP packet capture; no general traffic capture."
    echo "Creates a timestamped ZIP in the current directory."
    exit 0
fi
if [ "$(uname -s)" != Darwin ]; then
    echo "This capture must run on the affected Mac." >&2
    exit 1
fi
if [ "$(id -u)" != 0 ]; then
    exec /usr/bin/sudo /bin/bash "$0" "$@"
fi

iface="${1:-}"
if [ -z "$iface" ]; then
    iface=$(/usr/sbin/networksetup -listallhardwareports | /usr/bin/awk '/Hardware Port: (Wi-Fi|AirPort|WLAN)/ {getline; print $2; exit}')
fi
case "$iface" in
    en[0-9]*) ;;
    *) echo "Pass the Wi-Fi interface explicitly, for example: /bin/bash $0 en0" >&2; exit 1 ;;
esac
if ! /sbin/ifconfig "$iface" >/dev/null 2>&1; then
    echo "Interface $iface does not exist." >&2
    exit 1
fi

capture_dir="$PWD/AirPortRTW-Switch-$(/bin/date -u +%Y%m%d-%H%M%S)-$$"
umask 077
/bin/mkdir -p "$capture_dir"
log_pid=""
sample_pid=""
packet_pid=""

mark() {
    /bin/echo "$(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$capture_dir/timeline.txt"
}
snapshot() {
    local name="$1"
    /usr/sbin/ioreg -a -r -c AirPortRTW > "$capture_dir/$name-driver.plist" 2> "$capture_dir/$name-driver-errors.txt"
    {
        /bin/date -u
        /sbin/ifconfig "$iface"
        /usr/sbin/ipconfig getpacket "$iface"
        /sbin/route -n get default
        /usr/sbin/scutil --nwi
    } > "$capture_dir/$name-network.txt" 2>&1
}
finish() {
    trap - EXIT INT TERM
    mark "CAPTURE_STOP"
    if [ -n "$sample_pid" ]; then kill "$sample_pid" 2>/dev/null; wait "$sample_pid" 2>/dev/null; fi
    if [ -n "$log_pid" ]; then kill "$log_pid" 2>/dev/null; wait "$log_pid" 2>/dev/null; fi
    if [ -n "$packet_pid" ]; then kill -INT "$packet_pid" 2>/dev/null; wait "$packet_pid" 2>/dev/null; fi
    snapshot after
    local zip_path="$capture_dir.zip"
    if /usr/bin/ditto -c -k --keepParent "$capture_dir" "$zip_path"; then
        if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
            /usr/sbin/chown -R "$SUDO_UID:$SUDO_GID" "$capture_dir" "$zip_path"
        fi
        /bin/echo "Saved: $zip_path"
    else
        /bin/echo "ZIP creation failed; capture files remain in: $capture_dir" >&2
    fi
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mark "CAPTURE_START interface=$iface"
snapshot before
/usr/bin/log stream --style compact --level info --predicate \
    '(process == "kernel" AND (eventMessage CONTAINS[c] "AirPortRTW" OR eventMessage CONTAINS[c] "rtw88")) OR process == "airportd" OR process == "configd" OR subsystem BEGINSWITH "com.apple.IPConfiguration"' \
    > "$capture_dir/system.log" 2>&1 &
log_pid=$!

# DHCP/ARP only, capped at 512 packets. Includes addressing/hostnames, not
# application traffic. BPF capture shows the BSD boundary, not proof of RF TX.
/usr/sbin/tcpdump -p -n -i "$iface" -s 0 -U -c 512 \
    -w "$capture_dir/dhcp-arp.pcap" 'arp or (udp and (port 67 or port 68))' \
    > "$capture_dir/packet-capture.log" 2>&1 &
packet_pid=$!

(
    while :; do
        /bin/echo "=== $(/bin/date -u +%Y-%m-%dT%H:%M:%SZ) ==="
        /usr/sbin/ipconfig getifaddr "$iface" || true
        /sbin/ifconfig "$iface" | /usr/bin/awk '/inet |status:/'
        /sbin/route -n get default 2>&1 | /usr/bin/awk '/gateway:|interface:|not in table/'
        # An IP probe separates reachability from DNS. ICMP may be filtered;
        # missing replies alone do not prove that the driver has no data path.
        /sbin/ping -n -c 1 -W 1000 1.1.1.1 2>&1
        /bin/sleep 1
    done
) > "$capture_dir/reachability.txt" 2>&1 &
sample_pid=$!

/bin/echo "Interface: $iface"
/bin/echo "Press Return immediately BEFORE selecting the other network in the macOS Wi-Fi menu."
read -r _
mark "USER_SWITCH_START"
/bin/echo "Switch now. Press Return again when Internet works OR when the attempt has failed."
read -r _
mark "USER_TEST_END"
exit 0

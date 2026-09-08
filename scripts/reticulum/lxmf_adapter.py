#!/usr/bin/env python3
# Reticulum LXMF adapter — T2.6.2 (ADR-0026 §3). A supervised co-process the
# station drives to move opaque carrier frames over LXMF. Unlike the T2.6.1 spike
# helper (throwaway), this is a supported component: it is the ONE place RNS/LXMF
# is spoken, because RNS exposes no language-neutral send/receive RPC (ADR-0026).
#
# It attaches to a running, station-supervised `rnsd` shared instance and:
#   - reads OUTBOUND messages on stdin  (station → adapter): {dest_hex, frame}
#     and sends each as an LXMF message carrying `frame` as opaque bytes;
#   - writes INBOUND messages on stdout (adapter → station): {source_hex, frame}
#     for each LXMF message delivered to us.
#
# Wire framing (both directions), matching rrn_station::reticulum::codec:
#   u32 body_len (BE) · u16 endpoint_len (BE) · endpoint (utf-8 hex) · frame bytes
#
# The adapter holds no RRN key. Its LXMF identity is a rotatable reachability
# handle (ADR-0013 "bind, do not collapse"); integrity of anything carried rides
# on the app-layer sealed/signed envelope, never on LXMF.
#
# Verified against rns==1.5.2 / lxmf==1.1.1.
import argparse
import os
import struct
import sys
import threading

import RNS
import LXMF


def read_exact(stream, n):
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            return None  # EOF
        buf += chunk
    return buf


def read_message(stream):
    header = read_exact(stream, 4)
    if header is None:
        return None
    (body_len,) = struct.unpack(">I", header)
    body = read_exact(stream, body_len)
    if body is None or len(body) < 2:
        return None
    (ep_len,) = struct.unpack(">H", body[:2])
    endpoint = body[2 : 2 + ep_len].decode("utf-8", "replace")
    frame = body[2 + ep_len :]
    return endpoint, frame


def write_message(stream_fd, endpoint, frame):
    ep = endpoint.encode("utf-8")
    body = struct.pack(">H", len(ep)) + ep + frame
    os.write(stream_fd, struct.pack(">I", len(body)) + body)


def load_or_create_identity(path):
    if os.path.isfile(path):
        return RNS.Identity.from_file(path)
    ident = RNS.Identity()
    ident.to_file(path)
    return ident


def main():
    p = argparse.ArgumentParser(description="T2.6.2 Reticulum LXMF adapter")
    p.add_argument("--config", required=True)
    p.add_argument("--identity", required=True)
    p.add_argument("--max-frame", type=int, default=500)
    args = p.parse_args()

    # Attach to the station-supervised rnsd shared instance (never own the
    # interfaces ourselves).
    RNS.Reticulum(args.config, require_shared_instance=True)
    router = LXMF.LXMRouter(storagepath=os.path.join(args.config, "lxmf_adapter"))
    identity = load_or_create_identity(args.identity)
    source = router.register_delivery_identity(identity, display_name="rrn-station")
    router.announce(source.hash)

    out_fd = sys.stdout.fileno()
    out_lock = threading.Lock()

    def on_delivery(message):
        src = message.source_hash.hex() if message.source_hash else ""
        with out_lock:
            write_message(out_fd, src, message.content)

    router.register_delivery_callback(on_delivery)

    # Periodically re-announce so late peers can find us.
    def announce_loop():
        import time

        while True:
            time.sleep(30)
            try:
                router.announce(source.hash)
            except Exception:
                pass

    threading.Thread(target=announce_loop, daemon=True).start()

    # Outbound loop: drain stdin, send each frame over LXMF.
    stdin = sys.stdin.buffer
    while True:
        msg = read_message(stdin)
        if msg is None:
            break  # station closed the pipe → shut down
        dest_hex, frame = msg
        try:
            dest_hash = bytes.fromhex(dest_hex)
        except ValueError:
            sys.stderr.write("bad destination hex: %r\n" % dest_hex)
            continue
        if not RNS.Transport.has_path(dest_hash):
            RNS.Transport.request_path(dest_hash)
            # LXMF will hold and retry; we drop this send if the identity is not
            # yet known, and the station's DtnSyncer resends on its own timer.
        recipient = RNS.Identity.recall(dest_hash)
        if recipient is None:
            sys.stderr.write("no path yet to %s; frame dropped, will be resent\n" % dest_hex)
            continue
        dest = RNS.Destination(
            recipient, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery"
        )
        lxm = LXMF.LXMessage(dest, source, frame, desired_method=LXMF.LXMessage.DIRECT)
        router.handle_outbound(lxm)


if __name__ == "__main__":
    main()

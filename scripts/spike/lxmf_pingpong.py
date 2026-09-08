#!/usr/bin/env python3
# SPIKE SUPPORT ONLY — T2.6.1 (ADR-0013). Not production code, not shipped to
# operators. This is the Python side of the Reticulum integration spike: it
# attaches to a running, station-supervised `rnsd` shared instance and moves one
# opaque LXMF message end to end. It exists because RNS/LXMF expose no
# language-neutral send/receive RPC — the supported programmatic surface is the
# in-process Python `RNS` + `LXMF` API (see ADR-0026). The Rust spike test
# (crates/rrn-station/tests/reticulum_spike.rs) orchestrates two of these against
# two supervised `rnsd` instances. Keep this small; it is deliberately not a
# reusable library.
#
# Verified against rns==1.5.2 / lxmf==1.1.1 (PyPI, 2026-08).
import argparse
import os
import sys
import time

import RNS
import LXMF

DELIVERED = False


def load_or_create_identity(path):
    if os.path.isfile(path):
        return RNS.Identity.from_file(path)
    ident = RNS.Identity()
    ident.to_file(path)
    return ident


def role_hash(args):
    # Print the LXMF delivery destination hash for a persisted identity, without
    # bringing up any interfaces — lets the orchestrator target a receiver that
    # has not started yet (the store-and-forward case).
    ident = load_or_create_identity(args.identity)
    dest_hash = RNS.Destination.hash(ident, "lxmf", "delivery")
    sys.stdout.write(dest_hash.hex() + "\n")
    sys.stdout.flush()


def role_recv(args):
    # require_shared_instance: fail unless a separately-running (station-
    # supervised) rnsd owns the interfaces, so the spike cannot pass with this
    # helper standing in as the RNS instance itself.
    RNS.Reticulum(args.config, require_shared_instance=True)
    router = LXMF.LXMRouter(storagepath=args.storage, enforce_stamps=False)
    ident = load_or_create_identity(args.identity)
    dest = router.register_delivery_identity(ident, display_name="spike-recv")

    def on_delivery(message):
        with open(args.out, "wb") as fh:
            fh.write(message.content)
        sys.stdout.write("LXMF-RECEIVED %d\n" % len(message.content))
        sys.stdout.flush()
        global DELIVERED
        DELIVERED = True

    router.register_delivery_callback(on_delivery)
    sys.stdout.write("LXMF-DEST %s\n" % dest.hash.hex())
    sys.stdout.flush()

    deadline = time.time() + args.timeout
    while not DELIVERED and time.time() < deadline:
        router.announce(dest.hash)  # keep announcing so a late sender finds us
        time.sleep(2)
    sys.exit(0 if DELIVERED else 2)


def role_send(args):
    RNS.Reticulum(args.config, require_shared_instance=True)
    router = LXMF.LXMRouter(storagepath=args.storage, enforce_stamps=False)
    ident = load_or_create_identity(args.identity)
    source = router.register_delivery_identity(ident, display_name="spike-send")

    peer = bytes.fromhex(args.peer)
    with open(args.payload, "rb") as fh:
        payload = fh.read()

    def on_state(message):
        if message.state == LXMF.LXMessage.DELIVERED:
            sys.stdout.write("LXMF-DELIVERED %d\n" % len(payload))
            sys.stdout.flush()
            global DELIVERED
            DELIVERED = True

    deadline = time.time() + args.timeout
    # Wait for a path to the receiver, requesting one if unknown; LXMF holds and
    # retries the outbound message until the receiver appears.
    if not RNS.Transport.has_path(peer):
        RNS.Transport.request_path(peer)
    recipient = None
    while time.time() < deadline:
        if RNS.Transport.has_path(peer):
            recipient = RNS.Identity.recall(peer)
            if recipient is not None:
                break
        time.sleep(1)
    if recipient is None:
        sys.stderr.write("no path to receiver within timeout\n")
        sys.exit(3)

    dest = RNS.Destination(
        recipient, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery"
    )
    lxm = LXMF.LXMessage(
        dest, source, payload, "spike", desired_method=LXMF.LXMessage.DIRECT
    )
    lxm.register_delivery_callback(on_state)
    router.handle_outbound(lxm)
    while not DELIVERED and time.time() < deadline:
        time.sleep(1)
    sys.exit(0 if DELIVERED else 4)


def main():
    p = argparse.ArgumentParser(description="T2.6.1 LXMF spike helper")
    p.add_argument("role", choices=["hash", "recv", "send"])
    p.add_argument("--config")
    p.add_argument("--storage")
    p.add_argument("--identity", required=True)
    p.add_argument("--out")
    p.add_argument("--payload")
    p.add_argument("--peer")
    p.add_argument("--timeout", type=float, default=60.0)
    args = p.parse_args()
    {"hash": role_hash, "recv": role_recv, "send": role_send}[args.role](args)


if __name__ == "__main__":
    main()

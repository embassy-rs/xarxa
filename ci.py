#!/usr/bin/env python3

"""Build and test every feature combination that has to keep working.

Every cargo invocation is collected first, then run. With `cargo-batch` the
whole list is handed to a single invocation, which compiles all of it as one
build graph: shared dependencies are built once and the whole thing saturates
the machine, instead of a few hundred cargo runs each ramping up and down on
its own.
"""

import os
import shlex
import shutil
import subprocess
import sys

CARGO_BATCH_INSTALL = (
    "cargo install --git https://github.com/embassy-rs/cargo-batch "
    "cargo --bin cargo-batch --locked"
)

# Every combination of the media / protocol / socket features is built. The
# media and protocol axes need at least one feature each (the crate root says so
# with a `compile_error!`); the socket axis may be empty.
MEDIA = [
    "medium-ethernet",
    "medium-ip",
    "medium-ieee802154",
    "medium-ethernet,medium-ip",
    "medium-ethernet,medium-ip,medium-ieee802154",
]
PROTOS = ["ipv4", "ipv6", "ipv4,ipv6"]
SOCKETS = [
    "",
    "raw-ethernet",
    "raw-ip",
    "raw-ethernet,raw-ip",
    "udp",
    "tcp",
    "raw-ethernet,raw-ip,udp",
    "raw-ethernet,raw-ip,tcp",
    "udp,tcp",
    "raw-ethernet,raw-ip,udp,tcp",
]

# Everything that adds code paths to a media/protocol/socket combination,
# without being a combination axis of its own.
COMBO_EXTRAS = "std,log,async,icmp-errors,icmp-ping-reply,packetmeta-timestamp,multicast,iface-bind"

# The other axes are checked against the full feature set only; combining them
# with all of the above would be thousands of builds for no extra coverage.
EXTRAS_BASE = "medium-ethernet,medium-ip,ipv4,ipv6,raw-ethernet,raw-ip,udp,tcp"
EXTRAS = [
    "",
    "defmt",
    "log",
    "std",
    "std,log",
    "std,defmt",
    "async",
    "std,log,async",
    "icmp-errors",
    "icmp-ping-reply",
    "async,icmp-errors",
    "iface-bind",
    "iface-bind,defmt",
    "packetmeta-id",
    "packetmeta-timestamp",
    "packetmeta-timestamp,defmt",
    "tcp-timestamps",
    "tcp-timestamps,defmt",
    "tcp-sack",
    "tcp-sack,defmt",
    "tcp-reno",
    "tcp-cubic",
    "ipv4-fragmentation",
    "ipv4-reassembly",
    "ipv4-fragmentation,ipv4-reassembly,defmt",
    "medium-ieee802154",
    "sixlowpan-fragmentation",
    "sixlowpan-reassembly",
    "sixlowpan-fragmentation,sixlowpan-reassembly,defmt",
    "dhcpv4",
    "dhcpv4,async",
    "dhcpv4,defmt",
    "dhcpv4-options",
    "dhcpv4-options,defmt",
    "dhcpv4-server",
    "dhcpv4-server,defmt",
    "dhcpv4,dhcpv4-server",
    "multicast",
    "multicast,defmt",
    "multicast,icmp-errors,icmp-ping-reply",
    "std,log,async,icmp-errors,icmp-ping-reply,packetmeta-timestamp,tcp-timestamps,tcp-sack,"
    "packet-log,dhcpv4,dhcpv4-options,dhcpv4-server,multicast,ipv4-fragmentation,ipv4-reassembly,"
    "medium-ieee802154,sixlowpan-fragmentation,sixlowpan-reassembly,slaac",
]

# The whole API, minus the features that are mutually exclusive with another.
FULL = (
    "medium-ethernet,medium-ip,medium-ieee802154,ipv4,ipv6,raw-ethernet,raw-ip,udp,tcp,tcp-listener,"
    "std,log,async,icmp-errors,icmp-ping-reply,iface-bind,multicast,slaac,dhcpv4,dhcpv4-options,dhcpv4-server,"
    "dns,mdns,packetmeta-timestamp,tcp-timestamps,tcp-sack,ipv4-fragmentation,ipv4-reassembly,"
    "sixlowpan-fragmentation,sixlowpan-reassembly"
)


def join(*features):
    """Joins feature lists, dropping the empty ones."""
    return ",".join(f for f in features if f)


class Commands:
    """The cargo invocations to run, without the leading `cargo`."""

    def __init__(self):
        self.checks = []
        self.tests = []
        # Normalized feature lists of everything we run tests for. A `cargo
        # check` of a feature set we also test is pure duplicated work, since
        # the test build compiles the same code, so those are dropped.
        self.tested = set()
        # Feature sets already queued, so the same build is never run twice.
        self.queued = set()

    @staticmethod
    def _key(features):
        return frozenset(f for f in features.split(",") if f)

    def test(self, features, lib=True):
        """Runs the unit tests (and with `lib=False` everything else too)."""
        args = ["test"]
        if lib:
            args.append("--lib")
        args += ["--no-default-features", "--features", features]
        self.tests.append(args)
        self.tested.add(self._key(features))
        self.queued.add(self._key(features))

    def check(self, features):
        """Type-checks one feature set, unless it is already built by something."""
        key = self._key(features)
        if key in self.queued:
            return
        self.queued.add(key)
        self.checks.append(["check", "--no-default-features", "--features", features])

    def raw(self, args):
        """Runs a cargo invocation that is not about one feature list."""
        self.tests.append(args)

    def all(self):
        return self.checks + self.tests


def collect():
    cmds = Commands()

    # Tests. Everything testable is hosted (`std`) and logs through `log`, so the
    # `no_std` and `defmt` builds below are check-only. Unit tests are run for
    # every combination; the doc tests and the examples are built against the
    # default feature set only, since they are written against the whole API.
    #
    # These come first so that the checks below can skip what they already cover.
    for medium in MEDIA:
        for proto in PROTOS:
            for socket in SOCKETS:
                cmds.test(join("alloc", medium, proto, socket, COMBO_EXTRAS))

    for alloc in ["", "alloc"]:
        for extra in EXTRAS:
            cmds.check(join(EXTRAS_BASE, extra, alloc))

    for medium in MEDIA:
        for proto in PROTOS:
            for socket in SOCKETS:
                features = join(medium, proto, socket)
                # Bare, and with everything that adds code paths to the
                # combination. The `alloc` + extras one is what the test loop
                # above already builds, so `check` drops it.
                for alloc in ["", "alloc"]:
                    cmds.check(join(features, alloc))
                    cmds.check(join(features, COMBO_EXTRAS, alloc))

    # `xarxa-driver` on its own, every feature combination it has (it has few).
    # The combinations above only build it with the features xarxa forwards.
    for extra in ["", "defmt", "packetmeta-id", "packetmeta-timestamp", "packetmeta-timestamp,defmt"]:
        args = ["check", "-p", "xarxa-driver"]
        if extra:
            args += ["--features", extra]
        cmds.raw(args)
    cmds.raw(["test", "-p", "xarxa-driver"])

    cmds.raw(["test"])
    # Once more without `alloc`: the bounded containers and their full-table
    # paths. Unit tests only: the examples and doc tests are written against the
    # owned `Box`/`Vec` storage that only exists with `alloc`.
    cmds.test(FULL)
    # Once more with Reno congestion control: the default set has CUBIC, and the
    # two are mutually exclusive, so this is the default set with one swapped for
    # the other. (Without either feature TCP does no congestion control at all,
    # and the tests that exercise a congestion window are gated on `tcp-reno`.)
    cmds.test(join("alloc", FULL, "tcp-reno"), lib=False)
    cmds.raw(["build", "--examples"])

    return cmds.all()


def use_batch(count):
    """Whether to batch, warning about what makes us not to."""
    if shutil.which("cargo-batch") is None:
        print(
            f"WARNING: cargo-batch not found. Running {count} separate cargo invocations,\n"
            "         which is MUCH slower than batching them into one build. Install it with:\n"
            f"\n    {CARGO_BATCH_INSTALL}\n",
            file=sys.stderr,
        )
        return False

    # `cargo batch` takes any number of cargo invocations separated by `---` and
    # runs them as one build. Older versions only know `build`/`check`/`rustdoc`,
    # so probe for `test` before relying on it.
    probe = subprocess.run(
        ["cargo", "batch", "---", "test", "--help"], capture_output=True
    )
    if probe.returncode != 0:
        print(
            "WARNING: cargo-batch is installed but too old: it doesn't support 'test'.\n"
            "         Update it with the command below, or this will be slow.\n"
            f"\n    {CARGO_BATCH_INSTALL}\n",
            file=sys.stderr,
        )
        return False

    return True


def run(args, env):
    print(f"RUSTFLAGS={shlex.quote(env['RUSTFLAGS'])} {shlex.join(args)}", flush=True)
    code = subprocess.call(args, env=env)
    if code != 0:
        sys.exit(code)


def main():
    env = dict(os.environ)
    # Warnings are errors: the feature combinations are also checked for dead
    # code, which is what tells us a `#[cfg]` is missing somewhere.
    env["RUSTFLAGS"] = f"{env.get('RUSTFLAGS', '')} -D warnings".strip()

    cmds = collect()

    if use_batch(len(cmds)):
        batch = ["cargo", "batch"]
        for cmd in cmds:
            batch += ["---"] + cmd
        print(
            f"RUSTFLAGS={shlex.quote(env['RUSTFLAGS'])} cargo batch"
            f" ({len(cmds)} invocations)",
            flush=True,
        )
        code = subprocess.call(batch, env=env)
        sys.exit(code)

    # Each command is printed before it runs, so a failing step can be
    # reproduced by pasting the line. RUSTFLAGS is included because it is part
    # of what makes the step pass or fail.
    for cmd in cmds:
        run(["cargo"] + cmd, env)


if __name__ == "__main__":
    main()

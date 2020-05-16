# Copyright (c) Facebook, Inc. and its affiliates.
# SPDX-License-Identifier: GPL-3.0+

import errno
import os
import os.path
import shlex
import shutil
import socket
import subprocess
import tempfile

from util import nproc, out_of_date


# Script run as init in the virtual machine. This only depends on busybox. We
# don't assume that any regular commands are built in (not even echo or test),
# so we always explicitly run busybox.
_INIT_TEMPLATE = r"""#!{busybox} sh

set -eu

export BUSYBOX={busybox}
HOSTNAME=vmtest
VPORT_NAME=com.osandov.vmtest.0
# Set up overlayfs on the temporary directory containing this script.
mnt=$(dirname "$0")

trap '$BUSYBOX poweroff -f' EXIT

"$BUSYBOX" mount -t tmpfs tmpfs "$mnt"
"$BUSYBOX" mkdir -m 755 "$mnt/upper" "$mnt/work" "$mnt/merged"

"$BUSYBOX" mkdir -m 755 "$mnt/upper/dev" "$mnt/upper/etc" "$mnt/upper/mnt"
"$BUSYBOX" mkdir -m 555 "$mnt/upper/proc" "$mnt/upper/sys"
"$BUSYBOX" mkdir -m 1777 "$mnt/upper/tmp"

"$BUSYBOX" cat << EOF > "$mnt/upper/etc/hosts"
127.0.0.1 localhost
::1 localhost
127.0.1.1 $HOSTNAME.localdomain $HOSTNAME
EOF
: > "$mnt/upper/etc/resolv.conf"

"$BUSYBOX" mount -t overlay -o lowerdir=/,upperdir="$mnt/upper",workdir="$mnt/work" overlay "$mnt/merged"
"$BUSYBOX" pivot_root "$mnt/merged" "$mnt/merged/mnt"
cd /
"$BUSYBOX" umount -l /mnt

"$BUSYBOX" mount -t devtmpfs -o nosuid,noexec dev /dev
"$BUSYBOX" mount -t proc -o nosuid,nodev,noexec proc /proc
"$BUSYBOX" mount -t sysfs -o nosuid,nodev,noexec sys /sys
# Ideally we'd just be able to create an opaque directory for /tmp on the upper
# layer. However, before Linux kernel commit 51f7e52dc943 ("ovl: share inode
# for hard link") (in v4.8), overlayfs doesn't handle hard links correctly,
# which breaks some tests.
"$BUSYBOX" mount -t tmpfs -o nosuid,nodev tmpfs /tmp

"$BUSYBOX" hostname "$HOSTNAME"
"$BUSYBOX" ip link set lo up

vport=
for vport_dir in /sys/class/virtio-ports/*; do
	if "$BUSYBOX" [ -r "$vport_dir/name" \
			-a "$("$BUSYBOX" cat "$vport_dir/name")" = "$VPORT_NAME" ]; then
		vport="${{vport_dir#/sys/class/virtio-ports/}}"
		break
	fi
done
if "$BUSYBOX" [ -z "$vport" ]; then
	"$BUSYBOX" echo "could not find virtio-port \"$VPORT_NAME\""
	exit 1
fi

set +e
"$BUSYBOX" sh -c {command}
rc=$?
set -e

"$BUSYBOX" echo "Exited with status $rc"
"$BUSYBOX" echo "$rc" > "/dev/$vport"
"""


def install_vmlinux_precommand(command: str, vmlinux: str) -> str:
    vmlinux = shlex.quote(os.path.abspath(vmlinux))
    return fr""""$BUSYBOX" mkdir -m 755 -p /boot &&
	release=$("$BUSYBOX" uname -r) &&
	"$BUSYBOX" ln -sf {vmlinux} "/boot/vmlinux-$release" &&
	{command}"""


def _compile(
    *args: str,
    CPPFLAGS: str = "",
    CFLAGS: str = "",
    LDFLAGS: str = "",
    LIBADD: str = "",
) -> None:
    # This mimics automake: the order of the arguments allows for the default
    # flags to be overridden by environment variables, and we use the same
    # default CFLAGS.
    cmd = [
        os.getenv("CC", "cc"),
        *shlex.split(CPPFLAGS),
        *shlex.split(os.getenv("CPPFLAGS", "")),
        *shlex.split(CFLAGS),
        *shlex.split(os.getenv("CFLAGS", "-g -O2")),
        *shlex.split(LDFLAGS),
        *shlex.split(os.getenv("LDFLAGS", "")),
        *args,
        *shlex.split(LIBADD),
        *shlex.split(os.getenv("LIBS", "")),
    ]
    print(" ".join([shlex.quote(arg) for arg in cmd]))
    subprocess.check_call(cmd)


def _build_onoatimehack(dir: str) -> str:
    os.makedirs(dir, exist_ok=True)

    onoatimehack_so = os.path.join(dir, "onoatimehack.so")
    onoatimehack_c = os.path.relpath(
        os.path.join(os.path.dirname(__file__), "onoatimehack.c")
    )
    if out_of_date(onoatimehack_so, onoatimehack_c):
        _compile(
            "-o",
            onoatimehack_so,
            onoatimehack_c,
            CPPFLAGS="-D_GNU_SOURCE",
            CFLAGS="-fPIC",
            LDFLAGS="-shared",
            LIBADD="-ldl",
        )
    return onoatimehack_so


class LostVMError(Exception):
    pass


def run_in_vm(command: str, *, vmlinuz: str, build_dir: str) -> int:
    # multidevs was added in QEMU 4.2.0.
    if (
        "multidevs"
        in subprocess.run(
            ["qemu-system-x86_64", "-help"],
            stdout=subprocess.PIPE,
            universal_newlines=True,
        ).stdout
    ):
        multidevs = ",multidevs=remap"
    else:
        multidevs = ""

    onoatimehack = _build_onoatimehack(build_dir)

    with tempfile.TemporaryDirectory(prefix="drgn-vmtest-") as temp_dir, socket.socket(
        socket.AF_UNIX
    ) as server_sock:
        socket_path = os.path.join(temp_dir, "socket")
        server_sock.bind(socket_path)
        server_sock.listen()

        busybox = shutil.which("busybox")
        if busybox is None:
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), "busybox")
        init = os.path.abspath(os.path.join(temp_dir, "init"))
        with open(init, "w") as init_file:
            init_file.write(
                _INIT_TEMPLATE.format(
                    busybox=shlex.quote(busybox), command=shlex.quote(command)
                )
            )
        os.chmod(init, 0o755)
        with subprocess.Popen(
            [
                # fmt: off
                "qemu-system-x86_64", "-cpu", "host", "-enable-kvm",

                "-smp", str(nproc()), "-m", "2G",

                "-nodefaults", "-display", "none", "-serial", "mon:stdio",

                # This along with -append panic=-1 ensures that we exit on a
                # panic instead of hanging.
                "-no-reboot",

                "-virtfs",
                f"local,id=root,path=/,mount_tag=/dev/root,security_model=none,readonly{multidevs}",

                "-device", "virtio-serial",
                "-chardev", f"socket,id=vmtest,path={socket_path}",
                "-device",
                "virtserialport,chardev=vmtest,name=com.osandov.vmtest.0",

                "-kernel", vmlinuz,
                "-append",
                f"rootfstype=9p rootflags=trans=virtio,cache=loose ro console=0,115200 panic=-1 init={init}",
                # fmt: on
            ],
            env={
                **os.environ,
                "LD_PRELOAD": f"{onoatimehack}:{os.getenv('LD_PRELOAD', '')}",
            },
        ) as qemu:
            server_sock.settimeout(5)
            try:
                sock = server_sock.accept()[0]
            except socket.timeout:
                raise LostVMError(
                    f"QEMU did not connect within {server_sock.gettimeout()} seconds"
                )
            try:
                status_buf = bytearray()
                while True:
                    try:
                        buf = sock.recv(4)
                    except ConnectionResetError:
                        buf = b""
                    if not buf:
                        break
                    status_buf.extend(buf)
            finally:
                sock.close()
        if not status_buf:
            raise LostVMError("VM did not return status")
        if status_buf[-1] != ord("\n") or not status_buf[:-1].isdigit():
            raise LostVMError(f"VM returned invalid status: {repr(status_buf)[11:-1]}")
        return int(status_buf)


if __name__ == "__main__":
    import argparse
    import sys

    from vmtest.resolver import KernelResolver

    parser = argparse.ArgumentParser(
        description="run vmtest virtual machine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-d",
        "--directory",
        default="build/vmtest",
        help="directory for build artifacts and downloaded kernels",
    )
    parser.add_argument(
        "--lost-status",
        metavar="STATUS",
        type=int,
        default=128,
        help="exit status if VM is lost",
    )
    parser.add_argument(
        "-k",
        "--kernel",
        default=argparse.SUPPRESS,
        help="kernel to use (default: latest available kernel)",
    )
    parser.add_argument(
        "command",
        type=str,
        nargs=argparse.REMAINDER,
        help="command to run in VM (default: sh -i)",
    )
    args = parser.parse_args()

    with KernelResolver(
        [getattr(args, "kernel", "*")], download_dir=args.directory
    ) as resolver:
        kernel = next(iter(resolver))
        try:
            command = " ".join(args.command) if args.command else '"$BUSYBOX" sh -i'
            command = install_vmlinux_precommand(command, kernel.vmlinux)
            sys.exit(
                run_in_vm(
                    command=command, vmlinuz=kernel.vmlinuz, build_dir=args.directory
                )
            )
        except LostVMError as e:
            print("error:", e, file=sys.stderr)
            sys.exit(args.lost_status)

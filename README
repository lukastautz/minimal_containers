# minimal_containers
minimal_containers is a lightweight, container-like virtualisation program. It consists of the program `container` with the subcommands `start`, `start-all`, `kill` and `list` and is written in C.
The configs, logs and pids are saved in the directory `{PATH}/configs`, `{PATH}/logs` and `{PATH}/pids`, respectively (see config.h), by default PATH is `/containers`. A container is created by adding a config named `{PATH}/configs/{CONTAINER}` and starting it with `container start {CONTAINER}`.

## Installation
You should first install [dietlibc](https://www.fefe.de/dietlibc). Then call `make` and either copy `container` to a directory in `PATH` or add the current directory to `PATH`.

## Configuration
The config syntax is kept as easy as possible: there are key-value pairs which are written as `KEY=VALUE`.

Possible keys:
| Name                  | Required | Description                                                                                                                                                                                                    |
|-----------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `root`                | Yes      | The path of the root of the container (`debootstrap` can be used to create an initial rootfs)                                                                                                                  |
| `init`                | Yes      | The script/program executed when the container is started (When a @ precedes the path, the path is assumed to be outside of the container)                                                                     |
| `namespaces`          | Yes      | Sets what should be "virtualized"/unshared:<ul><li>`all`: All flags set, equals `uphti`</li><li>`u`: User namespace, if not set KVM is usable inside of the container</li><li>`p`: Pid namespace</li><li>`h`: Hostname namespace (UTS), hostname will be set to the container name</li><li>`t`: Time namespace, uptime will be reset</li><li>`i`: IPC namespace (warning: unix sockets cannot be shared between containers when activated!)</li></ul>                                                                                                                                                                                                           |
| `max_physical_memory` | No       | The maximum physical memory the container may use                                                                                                                                                              |
| `max_memory`          | No       | The maximum memory (physical + swap) the container may use                                                                                                                                                     |
| `cpu_share`           | No       | The "importance" of the container, a part of 1024                                                                                                                                                              |
| `net_classid`         | No       | The network packets of the container will be assigned the specified classid (can be used for example with iptables)                                                                                            |
| `mount`               | No       | (Can be used multiple times) (In the format `SOURCE:DEST`) The directory `SOURCE` will be available as `DEST` inside of the container. `container start` warns when mounting fails, but continues nevertheless |
| `mount_ro`            | No       | Same as `mount`, but read-only. When mounting fails, `container start` exits                                                                                                                                   |
| `iops_limit`          | No       | (Can be used multiple times) (In the format `MAJOR:MINOR IOPS`) Limits the maximum IOPS for a device                                                                                                           |
| `io_bw_limit`         | No       | (Can be used multiple times) (In the format `MAJOR:MINOR BYTES_PER_SECOND`) Limits the maximum throughput for a device                                                                                         |

If a line is empty or starts with a `#`, it is ignored. Comments **CANNOT** be inserted in the same line as a key-value-pair. Do NOT use Windows-style linebreaks.

## Starting a container
You can start a container with `container start {CONTAINER}`. When you want to debug something, you can use `container start -s {CONTAINER}` to start an interactive shell inside of the container (when you don't want to use `/bin/bash`, you can set the environment variable `SHELL` (When a @ precedes the path specified in `SHELL`, the path is assumed to be outside of the container)). The directories `{PATH}/configs`, `{PATH}/logs` and `{PATH}/pids` must exist.

## Stopping a container
You can stop a container with `container kill {CONTAINER}`. Warning: this `SIGKILL`'s all processes within the container - they have no chance to clean something up.

## Abstract unix sockets
Abstract unix sockets (often displayed starting with @, for example used by Xorg) are NOT unshared (blame Linux, network namespaces would be required, but that is currently not included in minimal_containers, feel free to open a PR).

## Tips
With Debian you should execute `rm /sbin/telinit && ln -s /bin/true /sbin/telinit` when starting a container, as there is no systemd and apt calls telinit which would try to contact systemd forever.
When you install xfce4, you have to pay attention that xfce4-session doesn't have the same pid in different containers, see abstract unix sockets.
The neccesary cgroup (v1) systems have to be mounted at `/sys/fs/cgroup{devices,memory,cpu,blkio,net_cls}`.

## Memory usage
On my servers, `container start` uses around 44 KiB RSS.

## Internals
minimal_containers uses cgroups to limit the resource usage, linux namespaces to isolate the containers from the system and chroot to change the root directory.
# netavark-sriov

`netavark-sriov` is a rootful [Podman](https://podman.io/) network plugin. The binary name is `sriov`. Each network attaches one SR-IOV virtual function to the network namespace Podman passes in. Containers that share a function are members of one pod. Two networks may share one namespace; one network may not.

The plugin does not create virtual functions, change `sriov_numvfs`, or change `sriov_drivers_autoprobe`. Those stay with the host's early-boot configuration. It also does not speak DHCP, run Aardvark, or publish host ports.

## Build

Rust 1.88 or newer, and `protoc` on `PATH`. The pinned `netavark` crate compiles a protobuf during its build.

```
cargo build --release
cargo test
```

`cargo test` does not need an SR-IOV device. It covers option parsing, VF selection against a fake sysfs tree, driver resolution, the state file, and redirect rendering.

## Install

```
sudo install -D -m 0755 target/release/sriov /usr/local/libexec/netavark/sriov
```

`/etc/containers/containers.conf`, or a drop-in under `/etc/containers/containers.conf.d/`:

```
[network]
netavark_plugin_dirs = ["/usr/local/libexec/netavark"]
```

`podman info --format '{{.Plugins.Network}}'` lists `sriov` after that. Podman must be rootful and must already be using the netavark backend.

The plugin runs `/sbin/ip`, `/usr/sbin/nft`, `/sbin/modprobe`, and, when a gateway is set, `/usr/sbin/arping`.

## Reserved virtual functions

`/etc/netavark/sriov-reserved.conf` is required. A missing file is an error, so a forgotten install cannot hand a passthrough function to a container. An empty file is valid when nothing is reserved. Blank lines and `#` comments are ignored. PCI addresses include the domain and are matched case-insensitively.

```
# PCI addresses the allocator must never use.
0000:00:01.0

# Optional. One line per parent. Omit it when modprobe -R is correct.
parent enp1s0f0 vf_driver iavf
```

The driver line wins over the VF's PCI modalias. `modprobe -R` must return exactly one module, and that module must not be `vfio-pci`. A function with any driver bound, including `vfio-pci`, is not allocated.

Leave `sriov_drivers_autoprobe` at `0`. Otherwise the kernel can rebind a function between teardown and the next setup.

## Network options

Podman stores these as `--opt key=value`. Booleans are lowercase `true` or `false`.

| Key | Required | Default | Meaning |
| --- | --- | --- | --- |
| `parent` | yes | | Physical-function netdev that owns the virtual functions. |
| `vlan` | yes | | VLAN id 1–4094, programmed on that function. |
| `mac` | yes | | Unicast MAC. Not multicast and not all-zero. |
| `ipv4` | yes | | Host address and prefix, such as `192.0.2.10/24`. A network or broadcast address is rejected. `/31` and `/32` are accepted. |
| `gateway` | no | | IPv4 gateway on the same subnet. |
| `ipv6_token` | no | SLAAC from the MAC | Interface identifier only, such as `::10`. The prefix comes from router advertisements. |
| `trusted` | no | `true` | `trust on` or `trust off`. |
| `spoofchk` | no | `false` | `spoofchk on` or `spoofchk off`. |
| `mtu` | no | driver default | 68–65535. |
| `metric` | no | kernel default | Metric of the IPv4 default route. |
| `no_ipv4_default_route` | no | `false` | When `true`, do not add an IPv4 default route even if `gateway` is set. |
| `no_ipv6_default_route` | no | `false` | When `true`, do not allow router advertisement to install an IPv6 default route. |
| `redirect` | no | | Comma-separated in-namespace nft redirects. No spaces. |

`redirect` grammar is `[family:]proto:dport:toport`. The family is `ip` (the default), `ip6`, or `inet`. `inet` installs the rule in both families. The protocol is `tcp` or `udp`. Ports are 1–65535. Example: `tcp:443:8443,inet:udp:53:5353`.

`interface_name` is not a network option. Podman passes the name inside the namespace (`eth0` by default). A quadlet sets it with `Network=name.network:interface_name=eth1`.

IPAM is `none`. Do not set Podman's `Subnet=` or `Gateway=`; put the address in `ipv4` and the gateway in `gateway`. Do not use `PublishPort`. A host port publish cannot reach a function that has moved into the container namespace. Use `redirect` instead.

IPv6 is SLAAC inside the namespace. `ipv6_enabled` stays false because Podman is not allocating an IPv6 subnet. `dns_enabled` stays false. Set DNS on the pod; Aardvark is not used.

## Quadlet

`PodmanArgs=--share net` keeps each container its own hostname. The pod's default share list includes the UTS namespace, which would force one hostname.

```
# app.network
[Network]
NetworkName=app
Driver=sriov
IPAMDriver=none
DisableDNS=true
Options=parent=enp1s0f0
Options=vlan=10
Options=mac=02:11:22:33:44:55
Options=ipv4=192.0.2.10/24
Options=gateway=192.0.2.1
Options=ipv6_token=::10
Options=redirect=tcp:443:8443

# app.pod
[Pod]
PodName=app
Network=app.network
DNS=192.0.2.53
DNSSearch=example.com
PodmanArgs=--share net

# app.container
[Container]
Pod=app.pod
HostName=app.example.com
```

Other containers in the pod set `Pod=app.pod` and their own `HostName=`. They do not set `Network=`. Podman attaches the network once, for the pod's network namespace.

Two networks in one pod take two virtual functions and can use different interface names:

```
[Pod]
PodName=app
Network=app-a.network:interface_name=eth0
Network=app-b.network:interface_name=eth1
DNS=192.0.2.53
DNSSearch=example.com
PodmanArgs=--share net
```

Put `redirect` on the network that should own those rules. Teardown of the other network does not remove them.

Setup picks the lowest free function index. A restart may get a different index; the MAC, VLAN, and address are programmed again. State is recorded under `/run/netavark-sriov/` (mode `0750`, files mode `0600`) and disappears on reboot, together with the functions. A missing state file makes teardown succeed.

Allocation is serialized with a lock at `/run/netavark-sriov/lock`. A network that is already attached to another namespace fails. Join that pod instead of attaching the network a second time.

## SELinux

On a distribution policy, `/usr/local/libexec/netavark/sriov` is `usr_t`. `container_runtime_t` can execute `bin_t` and cannot execute `usr_t`. `selinux/netavark-sriov.te` labels the binary `bin_t`, labels `/run/netavark-sriov` `container_var_run_t`, and allows the runtime domain to write sysfs and the state directory. It is a raw module: it does not need `selinux-policy-devel`.

```
checkmodule -M -m -o /tmp/netavark_sriov.mod selinux/netavark-sriov.te
semodule_package -o /tmp/netavark_sriov.pp -m /tmp/netavark_sriov.mod -f selinux/netavark-sriov.fc
sudo semodule -i /tmp/netavark_sriov.pp
sudo restorecon -v /usr/local/libexec/netavark/sriov
```

The module is source that compiles with `checkmodule`. Install it only on a host where you want it loaded. It has not been verified against an enforcing policy.

## License

Apache-2.0. See [LICENSE](LICENSE).

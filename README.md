# wmgwd2

`wmgwd2` is a distributed gateway daemon for [WiMoVE](https://github.com/WiMoVE-OSS).
I wrote this daemon as part of my bachelor's thesis.

The design of `wmgwd2` is inspired by [VRRP](https://datatracker.ietf.org/doc/html/rfc5798).
In VRRP, there needs to be one virtual router per overlay network.
This results in many messages that are sent between the gateways.
`wmgwd2` aims to use a single peer discovery mechanism for all overlay networks.

## Architecture

`wmgwd2` assumes that all gateways are in one L2 domain.
Each wmgwd2 process periodically broadcasts UDP packets to the hard-coded address `10.0.1.255`.
Each UDP packet contains an 8-byte unique ID.
Gateways listen for the messages of other gateways.

Using **highest random weight hashing** (also known as rendezvous hashing), each wmgwd2 process determines which gateway is responsible for a given overlay network.
`wmgwd2` then reconciles the network configuration with the determined assignment.

`wmgwd2` sends periodic gratuitous ARP responses.
Therefore, a running instance of FRR advertises BGP EVPN routes as needed.

When a gateway fails, its `wmgwd2` process is not able to send periodic advertisements.
Other processes recognize the failure, recompute the assignments and change their network state. 

## Configuration

| Name   | Default               | Explanation                                                                |
|--------|-----------------------|----------------------------------------------------------------------------|
| uid    |                       | Unique ID used in advertisements                                           |
| minvni | 1                     | Minimum VXLAN Network Identifier                                           |
| maxvni | 100                   | Maximum VXLAN Network Identifier                                           |

## Network Configuration

`wmgwd2` depends on a proper network interface configuration.
The program requires a `macvlan` interface on which it sets the `protodown` flag as required.
The interface name is hardcoded to `vrrp4-%d` where `%d` is replaced with the VNI. 

FRR requires a VXLAN interface with a bridge interface for BGP EVPN operations.
They can be coupled to the macvlan interface via a virtual Ethernet interface.
For VNI 100, the resulting network interface structure looks like this:

![image](https://github.com/rgwohlbold/wmgwd2/assets/25486288/7e057f1e-d3a9-4ce4-8522-504c07117912)

Currently, `wmgwd2` does not support IPv6 interfaces, so `vrrp100-6` need not exist.

An example FRR configuration that can be used with `wmgwd2` looks like this:

```
ip forwarding
ip nht resolve-via-default
ip6 nht resolve-via-default
router bgp 65000
  bgp router-id 10.0.1.11
  no bgp default ipv4-unicast
  neighbor fabric peer-group
  neighbor fabric remote-as 65000
  neighbor fabric capability extended-nexthop
  neighbor fabric ebgp-multihop 5
  neighbor fabric timers 1 3
  neighbor 10.0.1.17 peer-group fabric
  address-family l2vpn evpn
   neighbor fabric activate
   advertise-all-vni
   advertise-svi-ip
  exit-address-family
  !
!
router ospf
 ospf router-id 1.1.1.1
 network 0.0.0.0/0 area 0.0.0.0
!
```

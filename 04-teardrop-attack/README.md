# Teardrop IP Fragmentation Attack

## Scenario

A packet capture containing suspicious IPv4 fragmentation was analyzed to identify characteristics associated with a Teardrop-style denial-of-service attack.

The capture contains only 17 packets, with the malicious behavior concentrated in two UDP/IP fragments sent from:

```text
10.1.1.1 -> 129.111.30.27
```

Inspection of the fragment offsets and lengths reveals that the second fragment overlaps data already contained in the first fragment.

Overlapping IPv4 fragments are the defining behavior demonstrated by this capture.

## Objectives

* Identify fragmented IPv4 traffic
* Determine which fragments belong to the same datagram
* Calculate the byte ranges represented by each fragment
* Identify overlapping fragment data
* Explain why malformed fragmentation can affect packet reassembly
* Develop useful Wireshark filters for detecting fragmentation anomalies

## Initial Triage

| Item                  | Finding                    |
| --------------------- | -------------------------- |
| Total Packets         | 17                         |
| Suspicious Source     | `10.1.1.1`                 |
| Target                | `129.111.30.27`            |
| Protocol              | UDP over IPv4              |
| Source Port           | `31915`                    |
| Destination Port      | `20197`                    |
| IP Identification     | `242`                      |
| Suspicious Fragments  | 2                          |
| Attack Characteristic | Overlapping IPv4 fragments |

Most packets in the capture are unrelated background traffic.

The Teardrop behavior occurs in two adjacent packets carrying fragments of the same IPv4 datagram.

---

## Analysis

### 1. Fragmented IPv4 Datagram Identified

The suspicious packets originate from:

```text
10.1.1.1
```

and are sent to:

```text
129.111.30.27
```

Both packets contain:

```text
Identification: 242
```

The IPv4 Identification field allows the receiving system to associate fragments belonging to the same original datagram.

The first fragment contains:

```text
Source: 10.1.1.1
Destination: 129.111.30.27
Protocol: UDP

IP Identification: 242
Fragment Offset: 0
More Fragments: Set

IP Payload Length: 36 bytes
```

Because the first fragment begins at offset `0`, its payload occupies bytes:

```text
0 - 35
```

of the reconstructed IP payload.

It also contains the UDP header, revealing:

```text
Source Port: 31915
Destination Port: 20197
```

<p align="center">
  <img src="screenshots/01-first-fragment.png"/>
  <br/>
  <em>First Fragment</em>
</p>

---

### 2. Second Fragment Examined

The following packet has the same:

```text
Source IP
Destination IP
Protocol
IP Identification
```

indicating that it belongs to the same fragmented datagram.

Its IPv4 fields show:

```text
IP Identification: 242
Fragment Offset: 3
More Fragments: Not Set

IP Payload Length: 4 bytes
```

IPv4 fragment offsets are measured in units of eight bytes.

Therefore:

```text
Fragment Offset = 3 × 8
                = 24 bytes
```

The second fragment therefore represents payload bytes:

```text
24 - 27
```

<p align="center">
  <img src="screenshots/02-overlapping-fragment.png"/>
  <br/>
  <em>Second Fragment</em>
</p>

---

### 3. Fragment Overlap Identified

The two fragments cover the following byte ranges:

```text
Fragment 1: 0 ------------------------- 35
Fragment 2:                 24 --- 27
```

More explicitly:

```text
Fragment 1:
Bytes 0-35

Fragment 2:
Bytes 24-27
```

The second fragment starts at byte 24 even though the first fragment already extends through byte 35.

Therefore bytes:

```text
24
25
26
27
```

are supplied twice.

This creates a:

```text
4-byte overlap
```

between the IPv4 fragments.

This malformed overlap is the principal indicator of the Teardrop-style fragmentation behavior present in the capture.

---

## Normal vs. Malformed Fragmentation

Normal IPv4 fragmentation divides a large datagram into non-overlapping sections.

For example:

```text
Fragment 1: Bytes 0-999
Fragment 2: Bytes 1000-1999
Fragment 3: Bytes 2000-2499
```

Each fragment continues where the previous fragment ended.

The observed traffic instead resembles:

```text
Fragment 1: Bytes 0-35
Fragment 2: Bytes 24-27
```

The receiver must therefore determine how to handle two fragments claiming to contain data for the same portion of the original datagram.

---

## Why Fragment Overlap Matters

IPv4 fragmentation requires the destination system to reconstruct the original packet before processing the encapsulated transport-layer data.

Reassembly relies on fields including:

```text
Source IP
Destination IP
Protocol
Identification
Fragment Offset
More Fragments flag
```

Historically, some operating-system network stacks handled malformed and overlapping fragments incorrectly.

Teardrop-style attacks deliberately create conflicting fragment layouts in an attempt to trigger errors during reassembly.

Older vulnerable systems could crash or become unstable when processing these malformed fragments, resulting in denial of service.

Modern operating systems generally handle this specific historical attack safely, but overlapping fragments remain security-relevant because they can also create inconsistencies between:

```text
Endpoint interpretation
Firewall interpretation
IDS/IPS interpretation
```

This is why modern network security tools commonly perform IP fragment reassembly before inspecting higher-layer traffic.

---

## Packet Comparison

| Field              |      Fragment 1 |      Fragment 2 |
| ------------------ | --------------: | --------------: |
| Source             |      `10.1.1.1` |      `10.1.1.1` |
| Destination        | `129.111.30.27` | `129.111.30.27` |
| Protocol           |             UDP |    UDP fragment |
| IP Identification  |           `242` |           `242` |
| Fragment Offset    |             `0` |             `3` |
| Actual Byte Offset |             `0` |            `24` |
| IP Payload Length  |      `36` bytes |       `4` bytes |
| More Fragments     |             Set |         Not Set |
| Payload Range      |          `0-35` |         `24-27` |

The identical Identification value and endpoint information establish that the two packets belong to the same fragmented IPv4 datagram.

The conflicting byte ranges establish the overlap.

---

## Indicators and Artifacts

| Type                        | Value           |
| --------------------------- | --------------- |
| Source IP                   | `10.1.1.1`      |
| Destination IP              | `129.111.30.27` |
| Protocol                    | UDP             |
| Source Port                 | `31915`         |
| Destination Port            | `20197`         |
| IP Identification           | `242`           |
| First Fragment Offset       | `0`             |
| Second Fragment Offset      | `3`             |
| Second Fragment Byte Offset | `24`            |
| Overlap                     | `4 bytes`       |

These values are artifacts from the sample capture and are not general-purpose indicators of compromise.

---

## Detection Opportunities

### Identify Fragmented IPv4 Traffic

A useful Wireshark filter is:

```text
ip.flags.mf == 1 || ip.frag_offset > 0
```

This identifies packets that either:

* indicate additional fragments follow, or
* begin somewhere after the start of the original datagram.

---

### Isolate the Suspicious Datagram

The fragments in this capture can be isolated using:

```text
ip.id == 0x00f2
```

Wireshark may display IP ID `242` as hexadecimal:

```text
0x00f2
```

The endpoints can also be included:

```text
ip.src == 10.1.1.1 &&
ip.dst == 129.111.30.27
```

---

### Detect Fragment Overlap

Wireshark's IPv4 reassembly analysis may identify malformed or overlapping fragment behavior.

Fields and expert information related to:

```text
Fragment offset
Reassembled IPv4
Fragment overlap
Fragment overlap conflict
```

are especially useful when investigating suspicious fragmentation.

The important analytical step is to compare:

```text
Fragment offset
+
Fragment payload length
```

between packets sharing the same IP Identification value.

---

## Useful Wireshark Filters

```text
# All fragmented IPv4 traffic
ip.flags.mf == 1 || ip.frag_offset > 0

# Suspicious source
ip.src == 10.1.1.1

# Source and target
ip.src == 10.1.1.1 &&
ip.dst == 129.111.30.27

# Specific fragmented datagram
ip.id == 0x00f2

# Fragmented UDP traffic
udp || ip.frag_offset > 0
```

## Security Significance

The capture demonstrates how malformed IPv4 fragmentation can be used as an attack technique.

Rather than sending independent packets, the attacker constructs fragments that appear to belong to the same original datagram but provide conflicting data for the same byte positions.

The receiving system must attempt to reassemble these fragments before the UDP datagram can be processed.

Historically vulnerable systems could fail while handling these malformed overlapping ranges, allowing specially constructed packets to cause denial of service.

The capture also illustrates a broader network-security concern: fragmentation can make packet inspection more difficult because transport-layer information may be distributed across multiple packets.

Effective network monitoring therefore needs to consider packet reassembly rather than evaluating each fragment independently.

## Conclusion

Analysis identified two malformed IPv4 fragments sent from `10.1.1.1` to `129.111.30.27`.

Both packets use IP Identification value `242`, establishing that they belong to the same fragmented UDP datagram.

The first fragment contains 36 bytes of IP payload beginning at offset zero, covering bytes `0-35`.

The second fragment has an IPv4 fragment offset of `3`. Because fragment offsets are measured in eight-byte units, this corresponds to byte `24`. Its four-byte payload therefore occupies bytes `24-27`.

Those four bytes fall entirely within the byte range already supplied by the first fragment, creating a four-byte overlap.

This malformed fragmentation pattern demonstrates the fundamental mechanism of a Teardrop-style attack and highlights the importance of IPv4 reassembly when analyzing potentially malicious network traffic.

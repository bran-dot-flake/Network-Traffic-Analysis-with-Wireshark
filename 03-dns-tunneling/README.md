# Remote Shell Traffic on Common Service Ports

## Scenario

A packet capture containing suspicious traffic between several internal hosts was analyzed to determine whether DNS was being abused for command-and-control activity.

Initial inspection shows legitimate DNS queries alongside TCP connections to ports commonly associated with DNS, Telnet, FTP, and HTTP.

Further analysis reveals that one host is operating an interactive Windows command shell over multiple TCP ports. Although TCP port 53 is normally associated with DNS, the application data transmitted over that connection is not DNS protocol traffic.

This demonstrates why identifying traffic solely by port number can be misleading.

## Objectives

* Identify the systems involved
* Distinguish legitimate DNS traffic from suspicious TCP/53 activity
* Identify interactive command-shell traffic
* Recover commands and command output from the packet capture
* Compare the same remote shell operating over multiple service ports
* Identify network indicators useful for detecting protocol misuse

## Initial Triage

| Item               | Finding                |
| ------------------ | ---------------------- |
| Total Packets      | 131                    |
| Capture Duration   | ~99.7 seconds          |
| Suspected Operator | `192.168.1.3`          |
| Remote Host        | `192.168.1.2`          |
| DNS Server         | `192.168.1.1`          |
| Suspicious Ports   | TCP/53, TCP/23, TCP/80 |
| Additional Probing | TCP/21                 |
| Remote OS          | Windows XP             |

Three internal systems appear in the capture:

```text
192.168.1.1
192.168.1.2
192.168.1.3
```

The traffic can be broadly divided into:

1. Legitimate DNS traffic between `192.168.1.3` and `192.168.1.1`
2. TCP connections from `192.168.1.3` to `192.168.1.2`
3. Interactive Windows command-shell data transmitted across several TCP ports

---

## Analysis

### 1. Legitimate DNS Traffic

At the beginning of the capture, `192.168.1.3` sends several legitimate DNS queries to:

```text
192.168.1.1:53/UDP
```

Observed queries include:

```text
1.1.168.192.in-addr.arpa
www.www.com.lan
www.www.com
```

These packets use:

```text
UDP destination port 53
```

and contain valid DNS headers, questions, and responses.

Useful filter:

```text
dns
```

or:

```text
udp.port == 53
```

This establishes an important baseline: genuine DNS traffic is present in the capture and can be decoded normally by Wireshark.

---

### 2. Suspicious TCP Connection to Port 53

Later, `192.168.1.3` initiates a TCP connection to:

```text
192.168.1.2:53
```

The connection is established using a normal TCP three-way handshake.

However, the application data immediately reveals that this is not a normal DNS session.

The server sends:

```text
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\>
```

This is a Windows command prompt.

The client then sends:

```text
dir
```

and the remote system responds with a directory listing from:

```text
C:\
```

The returned data includes entries such as:

```text
Documents and Settings
Program Files
WINDOWS
Temp
WUTemp
AUTOEXEC.BAT
CONFIG.SYS
```

The operator eventually sends:

```text
exit
```

and the TCP session terminates.

### Key Finding

Although the connection uses:

```text
TCP/53
```

the payload is clearly not DNS.

Instead, TCP port 53 is being used as a transport channel for an interactive command shell.

This distinction is critical:

> A service port does not guarantee that the expected protocol is actually being transmitted.

Useful filter:

```text
tcp.port == 53
```

The legitimate DNS traffic can then be distinguished because it occurs over UDP/53 and decodes as DNS, while the suspicious TCP stream contains plaintext Windows shell data.

---

### 3. Command Reconstruction

Following the suspicious TCP/53 stream reconstructs the interactive session.

The approximate sequence is:

```text
Remote host:
Microsoft Windows XP [Version 5.1.2600]

C:\>

Operator:
dir

Remote host:
Volume in drive C has no label.
Volume Serial Number is FF47-80EB

Directory of C:\

...
Documents and Settings
Program Files
Temp
WINDOWS
WUTemp
...

C:\>

Operator:
exit
```

Because the traffic is unencrypted, both commands and their output are directly recoverable from the capture.

This gives an analyst visibility into not only the existence of the remote connection but also the actions performed through it.

---

### 4. FTP Port Probing

Following the TCP/53 session, `192.168.1.3` repeatedly attempts to connect to:

```text
192.168.1.2:21
```

The target responds with TCP resets:

```text
SYN
RST, ACK
```

No FTP application data is exchanged.

This indicates that TCP port 21 is closed or otherwise actively rejecting the connection.

Useful filter:

```text
tcp.port == 21
```

These attempts are distinct from the successful shell sessions.

---

### 5. Remote Shell on TCP/23

The operator later connects to:

```text
192.168.1.2:23
```

TCP port 23 is conventionally associated with Telnet.

However, the traffic again exposes the same raw Windows command shell:

```text
Microsoft Windows XP [Version 5.1.2600]

C:\>
```

The operator executes:

```text
dir
```

and receives the same directory listing.

The operator then enters:

```text
ls -la
```

The Windows shell responds:

```text
'ls' is not recognized as an internal or external command,
operable program or batch file.
```

This response further confirms that the session is interacting directly with a Windows command interpreter rather than a normal Telnet service.

The operator then sends:

```text
exit
```

### Security Significance

TCP/23 would normally suggest Telnet traffic, but the network payload demonstrates that the actual application is simply a command shell listening on that port.

---

### 6. Remote Shell on TCP/80

A third successful shell connection occurs on:

```text
192.168.1.2:80
```

TCP port 80 normally indicates HTTP.

However, instead of an HTTP response such as:

```text
HTTP/1.1 200 OK
```

the server immediately returns:

```text
Microsoft Windows XP [Version 5.1.2600]

C:\>
```

The operator again sends:

```text
dir
```

and receives the Windows directory listing.

The session ends after:

```text
exit
```

No HTTP headers, HTTP methods, or other valid HTTP protocol structures are present.

Therefore:

```text
TCP/80 != HTTP
```

in this particular connection.

Useful filter:

```text
tcp.port == 80
```

Following the TCP stream clearly exposes the command-shell communication.

---

## Port and Protocol Comparison

| Port   | Expected Service | Observed Activity    |
| ------ | ---------------- | -------------------- |
| UDP/53 | DNS              | Legitimate DNS       |
| TCP/53 | DNS              | Windows remote shell |
| TCP/21 | FTP              | Connection rejected  |
| TCP/23 | Telnet           | Windows remote shell |
| TCP/80 | HTTP             | Windows remote shell |

This comparison demonstrates why network monitoring should validate application-layer behavior rather than relying exclusively on well-known port assignments.

---

## Recovered Commands

The following commands were observed in the remote sessions:

```text
dir
ls -la
exit
```

The `dir` command successfully returned the contents of the Windows `C:\` directory.

The `ls -la` command failed because it is a Unix/Linux-style command and was executed inside a Windows command shell.

---

## Indicators and Artifacts

| Type                 | Value                         |
| -------------------- | ----------------------------- |
| Operator Host        | `192.168.1.3`                 |
| Remote Host          | `192.168.1.2`                 |
| DNS Server           | `192.168.1.1`                 |
| Remote OS            | Microsoft Windows XP 5.1.2600 |
| Shell Ports          | TCP/53, TCP/23, TCP/80        |
| Closed/Rejected Port | TCP/21                        |
| Commands             | `dir`, `ls -la`, `exit`       |
| Working Directory    | `C:\`                         |
| Volume Serial        | `FF47-80EB`                   |

These values are artifacts from the sample capture and are not general indicators of compromise.

---

## Detection Opportunities

### Traffic on DNS Port That Is Not DNS

A connection using TCP/53 should be investigated when its application data does not decode as DNS.

Useful filter:

```text
tcp.port == 53
```

An analyst can then compare the stream contents against legitimate DNS traffic.

---

### Cleartext Command Prompt Strings

Strings such as:

```text
Microsoft Windows XP
C:\>
Directory of C:\
```

appearing inside network payloads can indicate an exposed or tunneled command shell.

---

### Service/Protocol Mismatch

Traffic on a well-known port that does not match the expected application protocol is suspicious.

Examples from this capture include:

```text
TCP/53 -> command shell instead of DNS
TCP/23 -> raw Windows shell
TCP/80 -> command shell instead of HTTP
```

Network intrusion detection systems can use protocol-aware inspection to detect these mismatches.

---

## Useful Wireshark Filters

```text
# All legitimate decoded DNS traffic
dns

# UDP DNS traffic
udp.port == 53

# Suspicious TCP traffic using port 53
tcp.port == 53

# Traffic between operator and remote host
ip.addr == 192.168.1.2 &&
ip.addr == 192.168.1.3

# FTP connection attempts
tcp.port == 21

# Port 23 shell
tcp.port == 23

# Port 80 shell
tcp.port == 80

# TCP reset responses
tcp.flags.reset == 1

# Packets containing the Windows prompt
tcp contains "C:\\"
```

## Security Significance

The most important lesson from this capture is that **port numbers and application protocols are not equivalent**.

A firewall, analyst, or detection system that assumes all TCP/53 traffic is DNS or all TCP/80 traffic is HTTP could overlook suspicious activity.

In this capture, an interactive Windows command shell operates successfully over TCP ports normally associated with:

* DNS
* Telnet
* HTTP

Because the traffic is transmitted in plaintext, Wireshark can reconstruct commands and command output directly from the TCP streams.

Protocol-aware monitoring therefore provides substantially more visibility than port-based monitoring alone.

## Conclusion

Analysis of the capture identified `192.168.1.3` interacting with a Windows XP system at `192.168.1.2`.

Legitimate DNS requests were first observed between `192.168.1.3` and the DNS server at `192.168.1.1`. These used UDP port 53 and contained valid DNS protocol structures.

A later connection from `192.168.1.3` to `192.168.1.2:53/TCP` initially appeared to involve DNS based on its port number. Inspection of the application payload instead revealed an interactive Windows command prompt. The operator executed `dir` and received the contents of the remote `C:\` directory before terminating the session.

Equivalent Windows shell sessions subsequently occurred over TCP ports 23 and 80, while attempts to connect to TCP/21 were rejected.

The investigation demonstrates that port numbers alone cannot reliably identify application behavior. Examining actual packet payloads and reconstructing TCP streams can reveal command-and-control or remote-shell activity concealed behind otherwise common service ports.

# SMB3 Session Analysis

## Scenario

This capture contained SMB traffic between two Windows hosts.

Instead of just identifying SMB packets, I wanted to follow one session from beginning to end and understand what each stage looked like in Wireshark.

The session eventually included:

* SMB negotiation
* NTLM authentication
* Access to `IPC$`
* Opening the `srvsvc` named pipe
* SMB read and write activity

## Initial Triage

| Item           | Finding           |
| -------------- | ----------------- |
| SMB Client     | `192.168.199.132` |
| SMB Server     | `192.168.199.133` |
| Server Port    | TCP/445           |
| SMB Version    | SMB 3.1.1         |
| Authentication | NTLMSSP           |
| Share          | `IPC$`            |
| Named Pipe     | `srvsvc`          |

The session I focused on was:

```text
192.168.199.132 -> 192.168.199.133:445
```

A useful starting filter was:

```text
ip.addr == 192.168.199.132 &&
ip.addr == 192.168.199.133 &&
tcp.port == 445
```

---

## SMB Negotiation

After the TCP connection was established, the client sent an SMB `NEGOTIATE` request.

The client advertised support for several SMB versions:

```text
SMB 2.0.2
SMB 2.1
SMB 3.0
SMB 3.0.2
SMB 3.1.1
```

The server responded by selecting:

```text
SMB 3.1.1
```

<p align="center">
  <img src="screenshots/01-smb-negotiate.png"/>
  <br/>
  <em>SMB 3.1.1 selected during negotiation</em>
</p>

This was the first part of the session that made the sequence easy to follow: the two systems agreed on the SMB version before moving on to authentication.

Useful filter:

```text
smb2.cmd == 0
```

---

## Following the NTLM Authentication

Next came the SMB `SESSION_SETUP` messages.

The authentication data contained:

```text
NTLMSSP
```

so I knew NTLM was being used.

One of the server responses returned:

```text
STATUS_MORE_PROCESSING_REQUIRED
0xC0000016
```

At first glance, the word "status" made this look like it could be an error, but this is a normal part of the NTLM challenge-response process.

The client then sent another `SESSION_SETUP` containing the next part of the authentication exchange.

<p align="center">
  <img src="screenshots/02-ntlm-session-setup.png"/>
  <br/>
  <em>NTLM authentication during SMB session setup</em>
</p>

The exchange also exposed some Windows metadata, including hostnames such as:

```text
DESKTOP-2AEFM7G
DESKTOP-V1FA0UQ
```

and the string:

```text
Willi Wireshark
```

The credentials themselves weren't visible in plaintext, but the authentication traffic still revealed useful host and identity information.

---

## Authentication Failures

There were also several earlier session attempts that didn't succeed.

Those returned:

```text
STATUS_LOGON_FAILURE
0xC000006D
```

This was useful to compare against `STATUS_MORE_PROCESSING_REQUIRED`.

The difference matters:

```text
0xC0000016 -> authentication is still in progress
0xC000006D -> authentication failed
```

After several failed attempts, a later session returned:

```text
STATUS_SUCCESS
```

At that point I knew the client had successfully authenticated to the server.

The basic progression was:

```text
TCP Connection
      ↓
SMB NEGOTIATE
      ↓
SESSION_SETUP
      ↓
NTLM Challenge/Response
      ↓
STATUS_SUCCESS
```

---

## Connecting to IPC$

Once authentication succeeded, the client sent a `TREE_CONNECT` request for:

```text
\\192.168.199.133\IPC$
```

<p align="center">
  <img src="screenshots/03-ipc-tree-connect.png"/>
  <br/>
  <em>Successful connection to the IPC$ share</em>
</p>

`IPC$` is different from a normal file share. It is commonly used for Windows interprocess communication and remote administrative activity.

Seeing it here wasn't automatically suspicious. It just told me that the client was moving beyond authentication into Windows service communication.

Useful filter:

```text
smb2.cmd == 3
```

---

## Opening the srvsvc Named Pipe

After connecting to `IPC$`, the client sent an SMB `CREATE` request for:

```text
srvsvc
```

The server accepted it.

`srvsvc` is a Windows Server Service RPC named pipe and can be used for things like querying server information or enumerating network shares.

The sequence now looked like:

```text
TREE_CONNECT -> IPC$
        ↓
CREATE -> srvsvc
        ↓
RPC-related communication
```

This helped make sense of the packets that followed. SMB wasn't being used simply to copy a file—it was acting as the transport for Windows RPC communication.

---

## Read and Write Activity

After opening `srvsvc`, the session began exchanging SMB `WRITE` and `READ` requests.

The pattern included:

```text
WRITE Request
WRITE Response

READ Request
READ Response

WRITE Request
WRITE Response

READ Request
READ Response
```

<p align="center">
  <img src="screenshots/04-srvsvc-read-write.png"/>
  <br/>
  <em>SMB read and write activity through the srvsvc pipe</em>
</p>

These operations were carrying data through the named pipe.

That was one of the more useful things I took from the capture. SMB traffic doesn't necessarily mean someone is browsing a shared folder or transferring files. SMB can also carry higher-level Windows communication like RPC over named pipes.

---

## Session Flow

Putting everything together, the successful session looked like this:

```text
192.168.199.132                     192.168.199.133
      |                                    |
      | -------- TCP connection --------> |
      |                                    |
      | ------ SMB NEGOTIATE -----------> |
      | <----- SMB 3.1.1 selected ------- |
      |                                    |
      | ------ SESSION_SETUP -----------> |
      | <--- NTLM challenge/response ----- |
      |                                    |
      | ------ SESSION_SETUP -----------> |
      | <------ STATUS_SUCCESS ----------- |
      |                                    |
      | ------ TREE_CONNECT ------------> |
      |        \\server\IPC$               |
      | <--------- Success --------------- |
      |                                    |
      | ------ CREATE srvsvc ------------> |
      | <--------- Success --------------- |
      |                                    |
      | ------- WRITE / READ ------------> |
      | <------ WRITE / READ ------------- |
```

This was probably the clearest way to understand the capture as a whole.

---

## Useful Wireshark Filters

```text
# All SMB2 / SMB3 traffic
smb2

# SMB traffic between the two hosts
ip.addr == 192.168.199.132 &&
ip.addr == 192.168.199.133 &&
tcp.port == 445

# SMB negotiation
smb2.cmd == 0

# Session setup
smb2.cmd == 1

# Tree connections
smb2.cmd == 3

# CREATE requests
smb2.cmd == 5

# Read operations
smb2.cmd == 8

# Write operations
smb2.cmd == 9

# IOCTL
smb2.cmd == 11
```

## Takeaway

The most useful part of this capture was being able to follow an SMB session as a sequence instead of treating each packet independently.

The client and server first negotiated SMB 3.1.1, then worked through NTLM authentication. After several failed attempts, one session succeeded.

From there, the client connected to `IPC$`, opened the `srvsvc` named pipe, and began exchanging read and write data through SMB.

It also gave me a better baseline for what normal SMB activity can look like. Things like `IPC$`, `srvsvc`, and named-pipe traffic can appear in both legitimate administration and malicious lateral movement, so seeing them alone isn't enough to call the activity suspicious.

The surrounding context—who connected, whether authentication succeeded, what resource was opened, and what happened afterward—is what makes the traffic meaningful.

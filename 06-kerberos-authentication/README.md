# Kerberos Authentication and Service Ticket Analysis

## Scenario

A packet capture containing Kerberos authentication traffic from a Windows domain environment was analyzed to reconstruct the ticket-based authentication process.

The capture contains communication between a client and a Kerberos Key Distribution Center (KDC) over UDP port 88.

The traffic demonstrates:

* Authentication Server requests and responses
* Kerberos error handling
* Ticket Granting Ticket acquisition
* Ticket Granting Service requests
* Service ticket issuance
* Requests for HOST, CIFS, and LDAP services
* Multiple domain principals using Kerberos

A supplied Kerberos keytab can also be used to assist with decrypting portions of the Kerberos exchanges in Wireshark.

## Objectives

* Identify the Kerberos client and KDC
* Distinguish AS and TGS exchanges
* Identify Ticket Granting Ticket acquisition
* Identify requested service principals
* Examine Kerberos error handling
* Understand the role of the TGT and service tickets
* Use a supplied keytab to improve visibility into encrypted Kerberos data

## Initial Triage

| Item                | Finding          |
| ------------------- | ---------------- |
| Total Packets       | 32               |
| Capture Duration    | ~74.03 seconds   |
| Client              | `10.1.12.2`      |
| Kerberos KDC        | `10.5.3.1`       |
| Protocol            | Kerberos         |
| Transport           | UDP              |
| Server Port         | UDP/88           |
| Realm               | `DENYDC.COM`     |
| Observed Principals | `des`, `u5`      |
| Service Types       | HOST, CIFS, LDAP |

All packets in the capture are Kerberos exchanges between:

```text
10.1.12.2 <-> 10.5.3.1
```

The client sends requests to:

```text
10.5.3.1:88/UDP
```

which identifies `10.5.3.1` as the Kerberos KDC.

---

## Analysis

### 1. Kerberos Authentication Traffic Identified

Filtering for:

```text
kerberos
```

isolates the entire capture.

The traffic consists primarily of four Kerberos message types:

```text
AS-REQ
AS-REP
TGS-REQ
TGS-REP
```

These represent two major stages of Kerberos authentication.

The first stage obtains a:

```text
Ticket Granting Ticket (TGT)
```

while the second uses the TGT to request:

```text
service tickets
```

for individual network services.

The high-level process is:

```text
Client                         KDC
  |                             |
  | -------- AS-REQ ----------> |
  | <------- AS-REP ----------- |
  |                             |
  | -------- TGS-REQ ---------> |
  | <------- TGS-REP ---------- |
```

---

### 2. Initial AS-REQ

The first packet is an:

```text
AS-REQ
```

from:

```text
10.1.12.2 -> 10.5.3.1
```

for the principal:

```text
des
```

within the Kerberos realm:

```text
DENYDC
```

The request ultimately seeks a ticket for:

```text
krbtgt/DENYDC
```

The `krbtgt` account is the Kerberos Ticket Granting Service account.

A successful AS exchange provides the client with a Ticket Granting Ticket, which can later be presented when requesting access to individual services.

Useful filter:

```text
kerberos.msg_type == 10
```

for AS-REQ messages.

---

### 3. Kerberos Error Response

The KDC does not immediately return an AS-REP to the first request.

Instead, the second packet is:

```text
KRB-ERROR
```

with Kerberos error code:

```text
14
```

which corresponds to:

```text
KDC_ERR_ETYPE_NOSUPP
```

This indicates that the KDC does not support one or more of the encryption types proposed in the initial request.

The client subsequently sends another AS-REQ with a compatible encryption configuration.

This demonstrates that Kerberos authentication may involve negotiation or error handling before a ticket is successfully issued.

Useful filter:

```text
kerberos.msg_type == 30
```

---

### 4. Ticket Granting Ticket Obtained

The client sends a second:

```text
AS-REQ
```

and the KDC responds with:

```text
AS-REP
```

The response identifies:

```text
Realm: DENYDC.COM
Client Principal: des
```

and contains a ticket issued for:

```text
krbtgt/DENYDC.COM
```

This is the Ticket Granting Ticket.

The TGT allows the authenticated principal to request tickets for individual services without repeatedly transmitting or validating the user's long-term credential.

The flow is therefore:

```text
des
 ↓
AS-REQ
 ↓
KDC
 ↓
AS-REP
 ↓
TGT for krbtgt/DENYDC.COM
```

Useful filter for AS responses:

```text
kerberos.msg_type == 11
```

---

### 5. Service Ticket Request

After acquiring a TGT, the client begins sending:

```text
TGS-REQ
```

messages.

A TGS request contains the previously obtained TGT and asks the KDC for permission to access a particular service.

The KDC responds with:

```text
TGS-REP
```

containing a service ticket.

Useful filters:

```text
kerberos.msg_type == 12
```

for TGS-REQ and:

```text
kerberos.msg_type == 13
```

for TGS-REP.

---

### 6. HOST Service Ticket

One of the first service tickets issued is for:

```text
host/xp1.denydc.com
```

The exchange follows:

```text
10.1.12.2
    |
    | TGS-REQ
    v
10.5.3.1
    |
    | TGS-REP
    v

Service:
host/xp1.denydc.com
```

The `HOST` service principal is commonly associated with general Windows host authentication and several Windows services.

This demonstrates that Kerberos tickets are issued for specific service principals rather than simply granting unrestricted access to a remote system.

---

### 7. CIFS Service Tickets

Several ticket exchanges involve:

```text
cifs/VPC-W2K3ENT
```

and:

```text
cifs/vpc-w2k3ent.denydc.com
```

CIFS is associated with Windows SMB file sharing.

A ticket for:

```text
cifs/server
```

allows the requesting principal to authenticate to the server's SMB service using Kerberos.

The process can be summarized as:

```text
TGT
 ↓
TGS-REQ
 ↓
Request CIFS ticket
 ↓
KDC
 ↓
TGS-REP
 ↓
CIFS service ticket
```

This ticket could subsequently be presented to the SMB server rather than sending a password across the network.

---

### 8. LDAP Service Tickets

The capture also contains service-ticket requests for LDAP.

Observed service principals include:

```text
LDAP/vpc-w2k3ent.denyDC.com
```

and:

```text
ldap/vpc-w2k3ent.denyDC.com/denyDC.com
```

LDAP is heavily used within Active Directory for directory queries and domain operations.

Kerberos tickets issued for LDAP therefore allow authenticated clients to access Active Directory directory services.

This is especially relevant during Windows domain authentication because a workstation may request multiple tickets during a single logon or domain interaction.

---

### 9. Multiple Services Requested

The capture illustrates an important aspect of Kerberos:

> A single authenticated principal may obtain one TGT and then use it to request multiple individual service tickets.

Observed services include:

| Service  | Purpose                             |
| -------- | ----------------------------------- |
| `krbtgt` | Ticket Granting Ticket              |
| `host`   | Windows host services               |
| `cifs`   | SMB / Windows file sharing          |
| `ldap`   | Active Directory directory services |

The network may therefore contain many TGS requests even though the user authenticated only once.

---

### 10. Additional Principal: u5

Later in the capture, another AS exchange occurs for:

```text
u5@DENYDC.COM
```

The KDC returns an:

```text
AS-REP
```

for this principal.

Additional TGS exchanges then follow, again requesting access to services including:

```text
host
LDAP
ldap
cifs
krbtgt
```

This demonstrates multiple Kerberos principals using the same KDC infrastructure.

---

## Kerberos Message Types

| Message   | Number | Purpose                            |
| --------- | -----: | ---------------------------------- |
| AS-REQ    |     10 | Request initial authentication/TGT |
| AS-REP    |     11 | KDC returns TGT                    |
| TGS-REQ   |     12 | Request ticket for a service       |
| TGS-REP   |     13 | KDC returns service ticket         |
| KRB-ERROR |     30 | Kerberos error response            |

These message types provide a straightforward way to classify Kerberos activity in packet captures.

---

## Authentication Flow

The authentication sequence observed in the capture can be generalized as:

```text
               Kerberos Authentication

Client                                  KDC
  |                                      |
  | ------------ AS-REQ --------------> |
  |                                      |
  | <----------- KRB-ERROR ------------- |
  |                                      |
  | ------------ AS-REQ --------------> |
  |                                      |
  | <------------ AS-REP --------------- |
  |                TGT                   |
  |                                      |
  | ------------ TGS-REQ --------------> |
  |          TGT + service SPN           |
  |                                      |
  | <------------ TGS-REP ---------------|
  |            Service Ticket            |
  |                                      |
```

The client can repeat the TGS portion of the exchange for each service it needs to access.

---

## Keytab Analysis

The supplied keytab contains two Kerberos principals:

```text
des@DENYDC.COM
u5@DENYDC.COM
```

The key entries use different encryption types.

The `des` entry uses Kerberos encryption type:

```text
3
```

corresponding to DES-CBC-MD5.

The `u5` entry uses encryption type:

```text
23
```

corresponding to RC4-HMAC.

When configured in Wireshark, the keytab can allow the dissector to decrypt Kerberos structures for which the corresponding key is available.

This can provide visibility beyond the information that is transmitted in cleartext.

---

## Indicators and Artifacts

| Type                   | Value                         |
| ---------------------- | ----------------------------- |
| Kerberos Client        | `10.1.12.2`                   |
| KDC                    | `10.5.3.1`                    |
| KDC Port               | UDP/88                        |
| Realm                  | `DENYDC.COM`                  |
| Principal              | `des`                         |
| Principal              | `u5`                          |
| TGT Service            | `krbtgt/DENYDC.COM`           |
| HOST Service           | `host/xp1.denydc.com`         |
| CIFS Service           | `cifs/VPC-W2K3ENT`            |
| CIFS Service           | `cifs/vpc-w2k3ent.denydc.com` |
| LDAP Service           | `LDAP/vpc-w2k3ent.denyDC.com` |
| Initial Kerberos Error | `KDC_ERR_ETYPE_NOSUPP`        |

These values are artifacts from the controlled sample environment rather than indicators of compromise.

---

## Security Significance

Kerberos is central to authentication in Active Directory environments.

Understanding normal Kerberos exchanges is important because many common Active Directory attack techniques manipulate the same ticket infrastructure.

Examples include:

```text
Kerberoasting
AS-REP roasting
Pass-the-Ticket
Golden Ticket attacks
Silver Ticket attacks
Ticket theft
Delegation abuse
```

However, the presence of AS-REQ, AS-REP, TGS-REQ, or TGS-REP traffic alone does not indicate malicious behavior.

These messages occur continuously during legitimate Windows domain activity.

Analysts must instead examine factors such as:

* Which principal requested the ticket
* Which SPN was requested
* Encryption types
* Repeated authentication failures
* Unusual ticket lifetimes
* Unexpected service access
* Abnormally high volumes of TGS requests
* Relationships between users and requested services

This capture serves as a useful baseline for understanding normal ticket acquisition before investigating Kerberos attacks.

---

## Useful Wireshark Filters

```text
# All Kerberos traffic
kerberos

# Kerberos communication with the KDC
udp.port == 88

# AS-REQ
kerberos.msg_type == 10

# AS-REP
kerberos.msg_type == 11

# TGS-REQ
kerberos.msg_type == 12

# TGS-REP
kerberos.msg_type == 13

# Kerberos errors
kerberos.msg_type == 30

# Client/KDC communication
ip.addr == 10.1.12.2 &&
ip.addr == 10.5.3.1
```

## Conclusion

Analysis of the capture identified Kerberos authentication between client `10.1.12.2` and KDC `10.5.3.1` over UDP port 88.

The initial principal `des` first sent an AS-REQ that received a Kerberos encryption-type error. A subsequent AS request succeeded, and the KDC returned an AS-REP containing a Ticket Granting Ticket for `krbtgt/DENYDC.COM`.

The TGT was then used in multiple TGS exchanges to obtain service tickets for resources including:

```text
host/xp1.denydc.com
cifs/VPC-W2K3ENT
LDAP/vpc-w2k3ent.denyDC.com
cifs/vpc-w2k3ent.denydc.com
```

Later traffic also showed authentication activity involving the `u5` principal.

The capture demonstrates the two fundamental stages of Kerberos authentication: initial TGT acquisition through the Authentication Service and subsequent service-ticket acquisition through the Ticket Granting Service.

Understanding this normal authentication sequence provides an important baseline for investigating Kerberos-related attacks in Active Directory environments.

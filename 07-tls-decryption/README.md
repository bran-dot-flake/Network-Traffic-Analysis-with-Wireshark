# SSL/TLS Traffic Decryption with an RSA Private Key

## Scenario

An encrypted SSL/TLS packet capture was analyzed together with a supplied RSA private key.

Without decryption, the capture exposes the TCP connection and SSL/TLS handshake but hides the application-layer HTTP requests and responses inside encrypted Application Data records.

After the appropriate private key is configured in Wireshark, portions of the encrypted session can be decrypted and dissected as HTTP.

This case demonstrates:

* TLS/SSL handshake analysis
* Identification of an encrypted cipher suite
* The limitations of inspecting encrypted application traffic
* RSA-based TLS decryption
* Recovery of HTTP requests from encrypted traffic
* Why modern forward-secret TLS configurations behave differently

## Objectives

* Identify the TLS client and server
* Examine the SSL/TLS handshake
* Determine the negotiated protocol and cipher suite
* Observe encrypted Application Data
* Configure the supplied RSA private key
* Recover HTTP application-layer traffic
* Compare visibility before and after decryption

## Initial Triage

| Item             | Finding                  |
| ---------------- | ------------------------ |
| Total Packets    | 58                       |
| Capture Duration | ~12.37 seconds           |
| Client           | `127.0.0.1`              |
| Server           | `127.0.0.1`              |
| Server Port      | TCP/443                  |
| Connections      | 2                        |
| Protocol         | SSL 3.0                  |
| Cipher Suite     | RSA with AES-256-CBC-SHA |
| Cipher ID        | `0x0035`                 |
| Supplied Key     | RSA Private Key          |
| RSA Key Size     | 1024 bits                |

Two TLS connections are visible:

```text
127.0.0.1:38713 -> 127.0.0.1:443
127.0.0.1:38714 -> 127.0.0.1:443
```

Because both endpoints use the loopback address, the client and HTTPS server were operating on the same system when the traffic was captured.

---

## Analysis

### 1. TCP Connection Established

Before encrypted communication begins, the client establishes a normal TCP connection to:

```text
127.0.0.1:443
```

TCP port 443 conventionally indicates HTTPS.

The first connection uses:

```text
Client Port: 38713
Server Port: 443
```

and begins with the standard:

```text
SYN
SYN/ACK
ACK
```

three-way handshake.

Useful filter:

```text
tcp.port == 443
```

At this stage, TCP metadata such as endpoints, ports, packet sizes, and timing remain visible even though the eventual application data is encrypted.

---

### 2. SSL/TLS Handshake Begins

Following the TCP handshake, the client initiates cryptographic negotiation.

The server responds with an SSL/TLS:

```text
Server Hello
```

and selects protocol version:

```text
SSL 3.0
```

represented as:

```text
0x0300
```

The Server Hello also selects cipher suite:

```text
0x0035
```

corresponding to:

```text
TLS_RSA_WITH_AES_256_CBC_SHA
```

This cipher suite combines:

```text
RSA
    Key exchange/authentication

AES-256-CBC
    Symmetric encryption

SHA
    Message authentication
```

The use of RSA key exchange is especially important for this analysis because the corresponding server private key was provided with the capture.

---

### 3. Server Certificate Exchange

During the handshake, the server sends its certificate to the client.

The certificate contains the public key used by the client during RSA-based session establishment.

Conceptually:

```text
Server
  |
  | Public certificate
  v
Client

Client generates secret material
  |
  | Encrypts using server RSA public key
  v
Server

Server decrypts using RSA private key
```

The supplied file:

```text
rsasnakeoil2.key
```

contains the matching RSA private key.

Its PEM header is:

```text
-----BEGIN RSA PRIVATE KEY-----
```

and the key is:

```text
1024 bits
```

This allows Wireshark to reproduce cryptographic operations necessary to derive the historical session keys.

---

### 4. Client Key Exchange

The client subsequently sends a:

```text
Client Key Exchange
```

message.

Under this RSA-based cipher suite, the client encrypts key-exchange material using the server's RSA public key.

The server can decrypt that information with its private key.

Both sides can then independently derive the symmetric keys used for the encrypted SSL session.

This relationship is what makes retrospective decryption possible when the server's private RSA key is available.

---

### 5. Change Cipher Spec

After key establishment, the peers exchange:

```text
Change Cipher Spec
```

messages.

This indicates that subsequent communication will use the negotiated encryption parameters.

After this point, Wireshark begins displaying records as encrypted:

```text
Application Data
```

rather than immediately exposing HTTP requests and responses.

---

### 6. Encrypted Application Data

Without the RSA key configured, packets following the handshake contain SSL records such as:

```text
Content Type: Application Data
Version: SSL 3.0
Encrypted Application Data: ...
```

The raw bytes appear effectively random.

For example, the client sends a large SSL Application Data record immediately after completing the handshake.

Without decryption, an analyst can determine:

```text
Client IP
Server IP
Server port
TLS version
Cipher suite
Packet timing
Packet sizes
Connection duration
```

but cannot directly determine the HTTP request contained inside the encrypted payload.

This is the central security benefit provided by TLS.

---

## TLS Visibility Without Decryption

The network observer can see:

```text
127.0.0.1:38713 -> 127.0.0.1:443

SSL/TLS handshake
SSL version
Cipher suite
Certificate
Application Data record lengths
Timing
```

but the application-layer conversation remains hidden:

```text
Encrypted Application Data
        ↓
       ???
```

The HTTP request itself is not readable from the ciphertext alone.

---

### 7. RSA Private Key Loaded into Wireshark

The supplied:

```text
rsasnakeoil2.key
```

can be configured as an RSA private key in Wireshark.

In current Wireshark versions, this can typically be configured through the TLS protocol preferences / RSA Keys configuration.

After the key is loaded and the capture is reprocessed, Wireshark can derive the session encryption keys for this historical RSA key-exchange session.

The same packet that previously appeared only as:

```text
SSL Application Data
```

can now be dissected further as:

```text
HTTP
```

---

### 8. HTTP Request Recovered

One of the decrypted application records contains:

```text
GET / HTTP/1.1
```

The request includes HTTP headers such as:

```text
Host: localhost
```

and browser information identifying an older Firefox/Linux client.

This changes the analyst's visibility from:

```text
Encrypted Application Data
```

to:

```text
HTTP GET /
```

The network conversation can therefore now be analyzed at the application layer.

This demonstrates that encryption does not destroy the underlying protocol data—it prevents observers without the necessary cryptographic material from reading it.

---

### 9. Additional HTTP Resources Recovered

The decrypted traffic contains additional HTTP requests associated with loading the web page and its resources.

One request retrieves:

```text
/icons/debian/openlogo-25.jpg
```

This demonstrates that Wireshark is not merely identifying the initial HTTP request.

Once the TLS session is successfully decrypted, it can dissect multiple application-layer requests and responses transported through the encrypted connection.

The logical protocol stack becomes:

```text
Ethernet
   ↓
IPv4
   ↓
TCP
   ↓
SSL/TLS
   ↓
HTTP
```

Without the private key, only the layers through SSL/TLS can be meaningfully inspected.

With decryption, HTTP becomes visible as well.

---

## Before and After Decryption

### Before

```text
TCP/443
   ↓
SSL 3.0
   ↓
Application Data
   ↓
Encrypted bytes
```

Visible information:

```text
Endpoints
Ports
Certificates
Cipher suite
Packet sizes
Timing
```

Hidden information:

```text
HTTP methods
Request paths
HTTP headers
Page contents
Transferred resources
```

### After

```text
TCP/443
   ↓
SSL 3.0
   ↓
Decrypted Application Data
   ↓
HTTP
   ↓
GET / HTTP/1.1
```

The underlying web activity becomes directly inspectable.

---

## Why RSA Decryption Works Here

The negotiated cipher suite is:

```text
TLS_RSA_WITH_AES_256_CBC_SHA
```

The important component is:

```text
RSA
```

The client uses the server's RSA public key during key establishment.

Because the matching private key was supplied, Wireshark can recover the required secret information and derive the symmetric session keys.

This enables retrospective decryption of the recorded session.

---

## Why This Does Not Work for Most Modern TLS Traffic

Modern TLS deployments generally use ephemeral key exchange mechanisms such as:

```text
ECDHE
```

rather than static RSA key exchange.

With ephemeral Diffie-Hellman key exchange, possession of the server's RSA private key does not provide the ephemeral session secrets required to decrypt previously captured traffic.

This property is called:

```text
Forward Secrecy
```

Therefore, the technique demonstrated by this historical capture should not be interpreted as meaning that possession of a modern HTTPS server's private certificate key automatically permits decryption of captured sessions.

Modern TLS analysis commonly uses session-secret logging, such as a TLS key log file, when authorized plaintext visibility is required.

---

## Two TLS Connections

The capture contains two client TCP connections to the HTTPS server:

```text
Connection 1:
127.0.0.1:38713 -> 127.0.0.1:443

Connection 2:
127.0.0.1:38714 -> 127.0.0.1:443
```

The second connection also exchanges SSL/TLS handshake and encrypted application data.

Multiple HTTPS connections are normal browser behavior because clients may establish additional connections to retrieve page resources in parallel.

---

## Indicators and Artifacts

| Type                   | Value                           |
| ---------------------- | ------------------------------- |
| Client/Server Address  | `127.0.0.1`                     |
| HTTPS Server Port      | TCP/443                         |
| Client Port            | `38713`                         |
| Additional Client Port | `38714`                         |
| SSL/TLS Version        | SSL 3.0                         |
| Cipher Suite           | `TLS_RSA_WITH_AES_256_CBC_SHA`  |
| Cipher ID              | `0x0035`                        |
| Encryption             | AES-256-CBC                     |
| Key Exchange           | RSA                             |
| Integrity              | SHA                             |
| RSA Private Key Size   | 1024 bits                       |
| Recovered Protocol     | HTTP                            |
| Recovered Request      | `GET / HTTP/1.1`                |
| Additional Resource    | `/icons/debian/openlogo-25.jpg` |

These values are artifacts of an intentionally old SSL/TLS sample and should not be treated as representative of a secure modern TLS deployment.

---

## Security Significance

TLS prevents passive observers from directly reading application-layer network traffic.

Without cryptographic secrets, this capture exposes connection metadata but hides HTTP request paths, headers, and transferred content.

Once the appropriate RSA private key is available, however, this historical RSA-based session can be decrypted and the underlying HTTP reconstructed.

This illustrates two important security concepts:

1. Encryption significantly changes what network analysts can observe from packet captures.
2. The security properties of TLS depend heavily on the negotiated cryptographic configuration.

Modern forward-secret cipher suites were designed in part to prevent retrospective session decryption solely from compromise of a server's long-term private key.

---

## Useful Wireshark Filters

```text
# HTTPS/TLS traffic
tcp.port == 443

# TLS/SSL traffic
tls || ssl

# TLS handshake traffic
tls.handshake || ssl.handshake

# HTTP visible after successful decryption
http

# Initial HTTP request after decryption
http.request

# Traffic on first client connection
tcp.port == 38713

# Traffic on second client connection
tcp.port == 38714
```

Depending on the Wireshark version, this historical capture may be labeled under either `SSL` or `TLS`.

## Conclusion

Analysis of the capture identified two encrypted SSL connections between local clients and an HTTPS server at `127.0.0.1:443`.

The server negotiated SSL 3.0 and cipher suite `0x0035`, corresponding to RSA key exchange with AES-256-CBC encryption and SHA integrity protection.

Without decryption, the HTTP portion of the communication appears only as encrypted SSL Application Data.

The supplied 1024-bit RSA private key allows Wireshark to derive the necessary session keys for this historical RSA-based handshake. After decryption, previously hidden application traffic becomes visible, including an HTTP:

```text
GET / HTTP/1.1
```

request and requests for additional web resources.

The analysis demonstrates the difference between transport metadata and protected application content, while also illustrating why modern forward-secret TLS configurations cannot normally be decrypted retrospectively using only a server's long-term RSA private key.

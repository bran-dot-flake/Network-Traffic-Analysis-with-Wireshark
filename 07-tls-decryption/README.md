# TLS Traffic Decryption with an RSA Private Key

## Scenario

This capture contained HTTPS traffic along with a supplied RSA private key.

At first, Wireshark could show me the TLS handshake and connection details, but the actual web traffic was hidden inside encrypted Application Data.

I wanted to see whether the supplied key was enough to decrypt the session and recover the underlying HTTP traffic.

## Initial Triage

| Item            | Finding                        |
| --------------- | ------------------------------ |
| Client / Server | `127.0.0.1`                    |
| Server Port     | TCP/443                        |
| Protocol        | SSL 3.0                        |
| Cipher Suite    | `TLS_RSA_WITH_AES_256_CBC_SHA` |
| Cipher ID       | `0x0035`                       |
| Supplied Key    | RSA Private Key                |
| RSA Key Size    | 1024 bits                      |

Two HTTPS connections were present:

```text
127.0.0.1:38713 -> 127.0.0.1:443
127.0.0.1:38714 -> 127.0.0.1:443
```

Since both sides use the loopback address, the browser and web server were running on the same machine when the capture was taken.

---

## Looking at the TLS Handshake

I started with:

```text
tcp.port == 443
```

and followed the first connection.

After the TCP handshake, the server returned an SSL/TLS `Server Hello`.

The important fields were:

```text
Version: SSL 3.0
Cipher Suite: 0x0035
```

Wireshark identified `0x0035` as:

```text
TLS_RSA_WITH_AES_256_CBC_SHA
```

<p align="center">
  <img src="screenshots/01-tls-handshake.png"/>
  <br/>
  <em>SSL 3.0 Server Hello selecting cipher suite 0x0035</em>
</p>

The part that mattered most for this project was `RSA`.

This older TLS configuration uses RSA during key establishment, and the capture came with the matching server private key.

That meant retrospective decryption might actually be possible.

---

## What Was Visible Before Decryption

After the handshake completed, the traffic changed to:

```text
Application Data
```

<p align="center">
  <img src="screenshots/02-encrypted-application-data.png"/>
  <br/>
  <em>Encrypted SSL Application Data before loading the key</em>
</p>

At this point I could still see things like:

```text
Endpoints
Ports
TLS version
Cipher suite
Certificate information
Packet sizes
Timing
```

but I couldn't see the actual HTTP requests.

The application data just appeared as encrypted bytes.

That gave me a good baseline before trying the private key.

---

## Loading the RSA Private Key

The supplied key was:

```text
rsasnakeoil2.key
```

and contained a standard RSA private-key PEM header:

```text
-----BEGIN RSA PRIVATE KEY-----
```

I added it to Wireshark's TLS RSA-key configuration and reprocessed the capture.

Because this session used RSA key exchange, Wireshark could use the matching private key to recover the session secrets needed to decrypt the traffic.

The same packets that previously showed only:

```text
SSL Application Data
```

could now be dissected as:

```text
HTTP
```

That was the point where the capture became much more interesting.

---

## Recovering the HTTP Request

After decryption, filtering for:

```text
http.request
```

revealed the HTTP activity that had previously been hidden.

One of the recovered requests was:

```text
GET / HTTP/1.1
Host: localhost
```

<p align="center">
  <img src="screenshots/04-decrypted-resource.png"/>
  <br/>
  <em>HTTP requests visible after TLS decryption</em>
</p>

The difference was pretty dramatic.

Before:

```text
TCP/443
   ↓
SSL 3.0
   ↓
Application Data
   ↓
Encrypted bytes
```

After loading the key:

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

Instead of just knowing that encrypted traffic existed, I could now see what the browser was actually requesting.

---

## Recovering Additional Resources

The decrypted session also contained requests for page resources.

One example was:

```text
/icons/debian/openlogo-25.jpg
```

Wireshark could now parse these requests and responses as HTTP rather than treating them as opaque TLS records.

<p align="center">
  <img src="recovered/apache_pb.png"/>
  <br/>
  <em>Image recovered from the decrypted HTTP session</em>
</p>

This confirmed that decryption wasn't limited to a single request. Once the TLS session was successfully decrypted, the underlying web traffic could be analyzed normally.

---

## Why the RSA Key Worked Here

The key detail was the negotiated cipher suite:

```text
TLS_RSA_WITH_AES_256_CBC_SHA
```

With this older RSA-based key exchange, the server's long-term RSA key is involved in establishing the session secrets.

Because the matching private key was available, Wireshark could use it to derive the encryption keys for the recorded session.

That makes retrospective decryption possible for this particular capture.

---

## Why This Is Different from Modern TLS

This technique shouldn't be taken to mean that having a modern HTTPS server's private key automatically lets you decrypt old packet captures.

Modern TLS commonly uses ephemeral key exchange such as:

```text
ECDHE
```

which provides forward secrecy.

In that setup, the server's long-term private key does not contain the ephemeral session secrets needed to decrypt previously recorded traffic.

For modern authorized TLS analysis, a session key log file is usually a much more practical method.

---

## Useful Wireshark Filters

```text
# HTTPS traffic
tcp.port == 443

# SSL/TLS traffic
tls || ssl

# TLS handshake traffic
tls.handshake || ssl.handshake

# HTTP visible after decryption
http

# HTTP requests after decryption
http.request

# First TLS connection
tcp.port == 38713

# Second TLS connection
tcp.port == 38714
```

Depending on the Wireshark version, this older capture may appear under either `SSL` or `TLS`.

## Takeaway

The most useful part of this project was seeing the difference encryption makes during packet analysis.

Before loading the key, I could identify the TLS session, protocol version, cipher suite, certificate, and connection metadata, but the actual web activity was hidden.

After loading the matching RSA private key, Wireshark could decrypt the session and reveal the underlying HTTP requests and resources.

Seeing:

```text
Application Data
```

turn into:

```text
GET / HTTP/1.1
```

made the purpose of TLS much more concrete.

It also showed why the exact cryptographic configuration matters. This worked because the capture used an older RSA key-exchange cipher suite; modern forward-secret TLS sessions would not normally be decryptable later using only the server's private key.

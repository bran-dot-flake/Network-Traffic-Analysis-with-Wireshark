# HTTP Object Recovery

## Scenario

This capture contained regular web browsing traffic over HTTP.

Since the traffic wasn't encrypted, I wanted to see how much of the user's activity I could reconstruct directly from the packet capture and whether any transferred files could be recovered.

## Initial Triage

| Item         | Finding              |
| ------------ | -------------------- |
| Client       | `10.1.1.101`         |
| Web Server   | `10.1.1.1`           |
| Protocol     | HTTP                 |
| Server Port  | TCP/80               |
| Main Content | HTML and JPEG images |

Most of the interesting traffic was between:

```text
10.1.1.101 <-> 10.1.1.1
```

There was also some unrelated HTTP traffic to external addresses, but I kept the investigation focused on the local client and server.

---

## Identifying the Main HTTP Session

I started by checking the IPv4 conversations and found a large amount of traffic between `10.1.1.101` and `10.1.1.1`.

<p align="center">
  <img src="screenshots/01-ipv4-conversations.png"/>
  <br/>
  <em>IPv4 conversations in the capture</em>
</p>

Looking at the HTTP traffic made the roles clear:

```text
10.1.1.101 = HTTP client
10.1.1.1   = HTTP server
```

The client was connecting to TCP/80 and requesting resources from the server.

Useful filters:

```text
http

ip.addr == 10.1.1.101

ip.addr == 10.1.1.1

tcp.port == 80
```

---

## Looking at the HTTP Requests

Filtering for:

```text
http.request
```

showed exactly what the browser was requesting.

<p align="center">
  <img src="screenshots/02-http-requests.png"/>
  <br/>
  <em>HTTP GET requests from the client</em>
</p>

Some of the requests included:

```text
GET / HTTP/1.1
GET /Websidan/index.html HTTP/1.1
GET /Websidan/images/bg2.jpg HTTP/1.1
GET /Websidan/images/sydney.jpg HTTP/1.1
```

Later, the client requested several photographs:

```text
GET /Websidan/2004-07-SeaWorld/320/DSC07858.JPG HTTP/1.1
GET /Websidan/2004-07-SeaWorld/320/DSC07859.JPG HTTP/1.1
GET /Websidan/2004-07-SeaWorld/fullsize/DSC07858.JPG HTTP/1.1
```

The request headers also exposed information about the browser:

```text
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0) Opera 7.11 [en]
Host: 10.1.1.1
```

So before even recovering any files, the capture was already revealing the pages being visited, requested file names, and client software.

---

## Finding the Image Transfers

I then filtered for HTTP responses containing JPEG images:

```text
http.content_type == "image/jpeg"
```

Several image transfers appeared.

Examples included:

```text
/Websidan/images/bg2.jpg
/Websidan/images/sydney.jpg
/Websidan/2004-07-SeaWorld/320/DSC07858.JPG
/Websidan/2004-07-SeaWorld/320/DSC07859.JPG
```

One request stood out because it was much larger:

```text
/Websidan/2004-07-SeaWorld/fullsize/DSC07858.JPG
```

The server response showed:

```text
HTTP/1.1 200 OK
Server: Apache/2.0.40 (Red Hat Linux)
Content-Length: 191515
Content-Type: image/jpeg
```

<p align="center">
  <img src="screenshots/03-fullsize-http-stream.png"/>
  <br/>
  <em>Full-size JPEG transferred over HTTP</em>
</p>

It looked like the user had first loaded a smaller version of the image and then opened the full-size copy.

---

## Following the HTTP Session

I followed the TCP stream associated with the full-size image.

The client requested:

```text
GET /Websidan/2004-07-SeaWorld/fullsize/DSC07858.JPG HTTP/1.1
Host: 10.1.1.1
```

and the server responded with:

```text
HTTP/1.1 200 OK
Server: Apache/2.0.40 (Red Hat Linux)
Content-Length: 191515
Content-Type: image/jpeg
```

This was a useful example of how Wireshark can piece individual TCP packets back together into the original application-layer conversation.

Instead of seeing disconnected packets, I could see the request for the file followed by the server returning the image data.

---

## Recovering the Image

The final step was seeing whether the file could actually be reconstructed.

Wireshark provides:

```text
File -> Export Objects -> HTTP
```

which listed the objects transferred during the session.

<p align="center">
  <img src="screenshots/04-export-http-objects.png"/>
  <br/>
  <em>HTTP objects available for export</em>
</p>

From there, I was able to export files including:

```text
bg2.jpg
sydney.jpg
DSC07858.JPG
DSC07859.JPG
```

Most importantly, the full-size version of `DSC07858.JPG` could be recovered successfully.

<p align="center">
  <img src="recovered/DSC07858(1).JPG"/>
  <br/>
  <em>Recovered DSC07858 image</em>
</p>

That was the most interesting part of the capture for me. I wasn't just able to identify that an image had been transferred — I could reconstruct the actual file that the user viewed.

---

## Artifacts Observed

| Type            | Value          |
| --------------- | -------------- |
| Client          | `10.1.1.101`   |
| Web Server      | `10.1.1.1`     |
| Protocol        | HTTP           |
| Server Port     | TCP/80         |
| Server Software | Apache/2.0.40  |
| Server OS       | Red Hat Linux  |
| Browser         | Opera 7.11     |
| Recovered Image | `DSC07858.JPG` |
| Image Size      | 191,515 bytes  |
| MIME Type       | `image/jpeg`   |

These are artifacts from the sample capture rather than indicators of malicious activity.

---

## Useful Wireshark Filters

```text
# All HTTP traffic
http

# HTTP requests
http.request

# JPEG responses
http.content_type == "image/jpeg"

# Client traffic
ip.addr == 10.1.1.101

# Server traffic
ip.addr == 10.1.1.1

# HTTP traffic between the client and server
ip.addr == 10.1.1.101 &&
ip.addr == 10.1.1.1 &&
tcp.port == 80
```

## Takeaway

The biggest thing this capture showed me was how much information plain HTTP exposes.

I could see the exact resources the client requested, identify the browser and server software, follow the HTTP conversation, and ultimately recover the image being transferred.

The recovered JPEG made the risk much more concrete. An observer with access to the traffic wouldn't just know that someone visited a page, they could potentially reconstruct the content being viewed.

With HTTPS, the application-layer contents of this session would normally be encrypted, preventing this kind of direct inspection and file recovery.

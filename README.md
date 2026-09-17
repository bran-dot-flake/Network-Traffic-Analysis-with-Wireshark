# Network Traffic Analysis with Wireshark

![Status](https://img.shields.io/badge/Project-Complete-brightgreen)
![Wireshark](https://img.shields.io/badge/Wireshark-Network%20Analysis-1679A7?logo=wireshark\&logoColor=white)
![Protocols](https://img.shields.io/badge/Protocols-HTTP%20%7C%20SMB%20%7C%20Kerberos%20%7C%20TLS-555555)
![Focus](https://img.shields.io/badge/Focus-Packet%20Analysis-orange)

*A collection of Wireshark investigations focused on packet analysis, protocol behavior, network reconnaissance, authentication traffic, and encrypted communications.*

<sub>by: Brandon Chaney</sub>

---

This repository contains a collection of Wireshark investigations I worked through to practice packet analysis and get more comfortable understanding what network activity actually looks like on the wire.

The cases cover things like HTTP traffic, port scanning, malformed fragmentation, SMB and Kerberos authentication, remote-shell traffic, and TLS decryption.

Each folder contains a short walkthrough of what I found, the filters I used, and the packet evidence that helped me reach the conclusion.

## Investigations

| Case                                                                            | Focus                                                    |
| ------------------------------------------------------------------------------- | -------------------------------------------------------- |
| [01 - HTTP Object Recovery](./01-http-object-recovery/)                         | Recovering files from cleartext HTTP                     |
| [02 - Nmap Scan Analysis](./02-nmap-scan-analysis/)                             | Recognizing different Nmap scan patterns                 |
| [03 - Remote Shell Protocol Misuse](./03-remote-shell-protocol-misuse/)         | Identifying a Windows shell running over TCP/53          |
| [04 - Teardrop Fragmentation Attack](./04-teardrop-fragmentation-attack/)       | Investigating overlapping IPv4 fragments                 |
| [05 - SMB3 Session Analysis](./05-smb3-session-analysis/)                       | Following SMB negotiation, NTLM, and named-pipe activity |
| [06 - Kerberos Authentication Analysis](./06-kerberos-authentication-analysis/) | Following TGT and service-ticket requests                |
| [07 - TLS Decryption Analysis](./07-tls-decryption-analysis/)                   | Decrypting an older RSA-based TLS session                |

## Tools

* Wireshark
* Display filters
* TCP stream reconstruction
* HTTP object export
* Kerberos keytabs
* RSA private-key decryption

## Capture Source

The packet captures used in these investigations come from the official [Wireshark SampleCaptures](https://wiki.wireshark.org/SampleCaptures) collection and were used for educational packet-analysis practice.

## Goal

The goal of this project was simple: spend more time looking at real packet captures and get better at recognizing meaningful network behavior instead of only learning protocols in theory.

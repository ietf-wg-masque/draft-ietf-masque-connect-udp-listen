---
title: "Proxying Listener UDP in HTTP"
abbrev: "CONNECT-UDP Listen"
category: std
docname: draft-schinazi-connect-udp-listen-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: Transport
wg: MASQUE
venue:
  group: "MASQUE"
  type: "Working Group"
  mail: "masque@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/masque/"
  github: "DavidSchinazi/draft-schinazi-connect-udp-listen"
  latest: "https://DavidSchinazi.github.io/draft-schinazi-connect-udp-listen/draft-schinazi-connect-udp-listen.html"
keyword:
  - quic
  - http
  - datagram
  - udp
  - proxy
  - tunnels
  - quic in quic
  - turtles all the way down
  - masque
  - http-ng
  - listen
author:
  -
    ins: D. Schinazi
    name: David Schinazi
    org: Google LLC
    street: 1600 Amphitheatre Parkway
    city: Mountain View
    region: CA
    code: 94043
    country: United States of America
    email: dschinazi.ietf@gmail.com
  -
    ins: A. Singh
    name: Abhi Singh
    org: Google LLC
    street: 1600 Amphitheatre Parkway
    city: Mountain View
    region: CA
    code: 94043
    country: United States of America
    email: abhisinghietf@gmail.com
normative:
informative:
  WebRTC:
    title: "WebRTC"
    date: 2021-01-26
    seriesinfo:
      W3C: Recommendation
    target: "https://www.w3.org/TR/webrtc/"

--- abstract

The mechanism to proxy UDP in HTTP only allows each UDP Proxying request to
transmit to a specific host and port. This is well suited for UDP client-server
protocols such as HTTP/3, but is not sufficient for some UDP peer-to-peer
protocols like WebRTC. This document proposes an extension to UDP Proxying in
HTTP that enables such use-cases.

--- middle

# Introduction {#intro}

The mechanism to proxy UDP in HTTP {{!CONNECT-UDP=RFC9298}} allows creating
tunnels for communicating UDP payloads {{!UDP=RFC0768}} to a fixed host and
port. Combined with the HTTP CONNECT method (see {{Section 9.3.6 of
!HTTP=RFC9110}}), it allows proxying the majority of a Web Browser's HTTP
traffic. However WebRTC {{WebRTC}} relies on ICE {{?ICE=RFC8445}} to provide
connectivity between two Web browsers, and ICE relies on the ability to send and
receive UDP packets to multiple hosts. While in theory it might be possible to
accomplish this using multiple UDP Proxying HTTP requests, HTTP semantics
{{HTTP}} do not guarantee that distinct requests will be handled by the same
server. This can lead to the UDP packets being sent from distinct IP addresses,
thereby preventing ICE from operating correctly. Consequently, UDP Proxying
requests cannot enable WebRTC connectivity between peers.

This document describes an extension to UDP Proxying in HTTP that allows sending
and receiving UDP payloads to multiple hosts within the scope of a single UDP
Proxying HTTP request.

## Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses terminology from {{CONNECT-UDP}} and notational conventions
from {{!QUIC=RFC9000}}. This document uses the terms Integer and List from
{{Section 3 of !STRUCTURED-FIELDS=RFC8941}} to specify syntax and parsing.


# Proxied UDP Listener Mechanism

In unextended UDP Proxying requests, the target host is encoded in the HTTP
request path or query. For Listener UDP Proxying, it is instead conveyed in each
HTTP Datagram, see {{format}}.

When performing URI Template Expansion of the UDP Proxying template (see
{{Section 3 of CONNECT-UDP}}), the client sets both the target_host and the
target_port variables to the '*' character (ASCII character 0x2A).

Before sending its UDP Proxying request to the proxy, the client allocates an
even-numbered context ID, see {{Section 4 of CONNECT-UDP}}. The client then adds
the "connect-udp-listen" header field to its UDP Proxying request, with its
value set as the allocated context ID, see {{hdr}}.

# HTTP Datagram Payload Format {#format}

When HTTP Datagrams {{!HTTP-DGRAM=RFC9297}} associated with this Listener UDP
Proxying request contain the context ID in the connect-udp-listen header field,
the format of their UDP Proxying Payload field (see {{Section 5 of
CONNECT-UDP}}) is defined by {{dgram-format}}:

~~~ ascii-art
Listener UDP Proxying Payload {
  IP Version (8),
  IP Address (32..128),
  UDP Port (16),
  UDP Payload (..),
}
~~~
{: #dgram-format title="Listener UDP Proxying HTTP Datagram Format"}

IP Version:

: The IP Version of the following IP Address field. MUST be 4 or 6.

IP Address:

: The IP Address of this proxied UDP packet. When sent from client to proxy,
this is the target host to which the proxy will send this UDP payload. When sent
from proxy to client, this represents the source IP address of the UDP packet
received by the proxy. This field has a length of 32 bits when the corresponding
IP Version field value is 4, and 128 when the IP Version is 6.

UDP Port:

: The UDP Port of this proxied UDP packet in network byte order. When sent from
client to proxy, this is the target port to which the proxy will send this UDP
payload. When sent from proxy to client, this represents the source UDP port of
the UDP packet received by the proxy.

UDP Payload:

: The unmodified UDP Payload of this proxied UDP packet (referred to as "data
octets" in {{UDP}}).


# The connect-udp-listen Header Field {#hdr}

The "connect-udp-listen" header field’s value is an Integer. It is set as the
Context ID. Any other value type MUST be handled as if the field were not
present by the recipients (for example, if this field is defined multiple times,
its type becomes a List and therefore is to be ignored). This document does not
define any parameters for the connect-udp-listen header field value, but future
documents might define parameters. Receivers MUST ignore unknown parameters.

# Security Considerations

The security considerations described in {{Section 7 of CONNECT-UDP}} also apply
here.

# IANA Considerations

This document will request IANA to register the following entry in the "HTTP
Field Name" registry maintained at
<[](https://www.iana.org/assignments/http-fields)>:

Field Name:
: connect-udp-listen

Template:
: None

Status:
: provisional (permanent if this document is approved)

Reference:
: This document

Comments:

: None
{: spacing="compact"}

--- back

# Example

In the example below, the client is configured with URI Template
"https://example.org/.well-known/masque/udp/{target_host}/{target_port}/" and
wishes to use WebRTC with another browser over a listener UDP Proxying tunnel.
It contacts a STUN server at 192.0.2.42. The STUN server, in response, sends the
proxy's IP address to the other browser at 203.0.113.33. Using this information,
the other browser sends a UDP packet to the proxy, which is proxied over HTTP
back to the client.

~~~ ascii-art
 Client                                             Server

 STREAM(44): HEADERS            -------->
   :method = CONNECT
   :protocol = connect-udp
   :scheme = https
   :path = /.well-known/masque/udp/*/*/
   :authority = proxy.example.org
   connect-udp-listen = 2
   capsule-protocol = ?1

 DATAGRAM                       -------->
   Quarter Stream ID = 11
   Context ID = 2
   IP Version = 4
   IP Address = 192.0.2.42
   UDP Port = 1234
   UDP Payload = Encapsulated UDP Payload

            <--------  STREAM(44): HEADERS
                         :status = 200
                         capsule-protocol = ?1

/* Wait for STUN server to respond to UDP packet. */

            <--------  DATAGRAM
                         Quarter Stream ID = 11
                         Context ID = 2
                         IP Version = 4
                         IP Address = 192.0.2.42
                         UDP Port = 1234
                         UDP Payload = Encapsulated UDP Payload

/* Wait for the STUN server to send the proxy's IP and */
/* port to the other browser and for the other browser */
/* to send a UDP packet to the proxy. */

            <--------  DATAGRAM
                         Quarter Stream ID = 11
                         Context ID = 2
                         IP Version = 4
                         IP Address = 203.0.113.33
                         UDP Port = 4321
                         UDP Payload = Encapsulated UDP Payload
~~~

# Comparison with CONNECT-IP

While the use-cases described in {{intro}} could be supported using IP Proxying
in HTTP {{?CONNECT-IP=I-D.ietf-masque-connect-ip}}, it would require that every
HTTP Datagram carries a complete IP header. This would lead to both
inefficiencies in the wire encoding and reduction in available Maximum
Transmission Unit (MTU). Furthermore, Web browsers would need to support IPv4
and IPv6 header generation, parsing, validation and error handling.

# Acknowledgments
{:numbered="false"}

This proposal is the result of many conversations with MASQUE working group
participants.

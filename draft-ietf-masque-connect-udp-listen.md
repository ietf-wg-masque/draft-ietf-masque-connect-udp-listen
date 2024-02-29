---
title: "Proxying Binding UDP in HTTP"
abbrev: "CONNECT-UDP Bind"
category: std
docname: draft-ietf-masque-connect-udp-bind-latest
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
  github: "ietf-wg-masque/draft-ietf-masque-connect-udp-listen"
  latest: "https://ietf-wg-masque.github.io/draft-ietf-masque-connect-udp-listen/draft-ietf-masque-connect-udp-listen.html"
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
  - bind
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


# Proxied UDP Binding Mechanism {#mechanism}

In unextended UDP Proxying requests, the target host is encoded in the HTTP
request path or query. For Binding UDP Proxying, it is instead conveyed in each
HTTP Datagram, see {{format}}.

When performing URI Template Expansion of the UDP Proxying template (see
{{Section 3 of CONNECT-UDP}}), the client sets both the target_host and the
target_port variables to the '*' character (ASCII character 0x2A).

Before sending its UDP Proxying request to the proxy, the client allocates an
even-numbered context ID, see {{Section 4 of CONNECT-UDP}}. The client then adds
the "connect-udp-bind" header field to its UDP Proxying request, with its
value set as the allocated context ID, see {{hdr}}.

# HTTP Datagram Payload Format {#format}

When HTTP Datagrams {{!HTTP-DGRAM=RFC9297}} associated with this Binding UDP
Proxying request contain the context ID in the connect-udp-bind header field,
the format of their UDP Proxying Payload field (see {{Section 5 of
CONNECT-UDP}}) is defined by {{dgram-format}}:

~~~ ascii-art
Binding UDP Proxying Payload {
  IP Version (8),
  IP Address (32..128),
  UDP Port (16),
  UDP Payload (..),
}
~~~
{: #dgram-format title="Binding UDP Proxying HTTP Datagram Format"}

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


# The connect-udp-bind Header Field {#hdr}

The "connect-udp-bind" header field’s value is an Integer. It is set as the
Context ID allocated for Binding UDP Proxying; see {{mechanism}}. Any other
value type MUST be handled as if the field were not present by the recipients
(for example, if this field is defined multiple times, its type becomes a List
and therefore is to be ignored). This document does not define any parameters
for the connect-udp-bind header field value, but future documents might define
parameters. Receivers MUST ignore unknown parameters.

# Proxy behavior

After accepting the Connect-UDP Binding proxying request, the proxy uses a UDP
port to transmit UDP payloads received from the client to the target IP Address
and UDP Port specified in each binding Datagram Payload received from the
client. The proxy uses the same port to listen for UDP packets from any
authorized target and encapsulates the packets in the Binding Datagram
Payload format, specifying the IP and port of the target and forwards it to
the client.

# Security Considerations

The security considerations described in {{Section 7 of CONNECT-UDP}} also apply
here. Since TURN can be run over this mechanism, implementors should review the
security considerations in {{Section 21 of ?TURN=RFC8656}}.

Since unextended UDP Proxying requests carry the target as part of the request,
the proxy can protect unauthorized targets by rejecting requests before creating
the tunnel, and communicate the rejection reason in response header fields.
Binding UDP Proxying requests do not have this ability. Therefore, proxies MUST
validate the target on every datagram and MUST NOT forward individual datagrams
with unauthorized targets. Proxies can either silently discard such datagrams or
abort the corresponding request stream.

Unlike non-binding CONNECT-UDP, since the proxy tunnels datagrams from any
target to clients bound to their respective public IP and ports, the clients
MUST be ready to handle potential unwanted traffic from unknown destinations.

# IANA Considerations

This document will request IANA to register the following entry in the "HTTP
Field Name" registry maintained at
<[](https://www.iana.org/assignments/http-fields)>:

Field Name:
: connect-udp-bind

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
wishes to use WebRTC with another browser over a Binding UDP Proxying tunnel.
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
   connect-udp-bind = 2
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

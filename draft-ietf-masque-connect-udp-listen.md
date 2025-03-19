---
title: "Proxying Bound UDP in HTTP"
abbrev: "CONNECT-UDP Bind"
category: std
docname: draft-ietf-masque-connect-udp-listen-latest
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
connectivity between two Web browsers, and ICE relies on the ability to send
and receive UDP packets to multiple hosts. While in theory it might be possible
to accomplish this using multiple UDP Proxying HTTP requests, HTTP semantics
{{HTTP}} do not guarantee that distinct requests will be handled by the same
server. This can lead to the UDP packets being sent from distinct IP addresses,
thereby preventing ICE from operating correctly. Consequently, UDP Proxying
requests cannot enable WebRTC connectivity between peers.

This document describes an extension to UDP Proxying in HTTP that allows
sending and receiving UDP payloads to multiple hosts within the scope of a
single UDP Proxying HTTP request.

## Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses terminology from {{CONNECT-UDP}} and notational conventions
from {{!QUIC=RFC9000}}. This document uses the terms Boolean, Integer, and List
from {{Section 3 of !STRUCTURED-FIELDS=RFC8941}} to specify syntax and parsing.
This document uses Augmented Backus-Naur Form and parsing/serialization
behaviors from {{!ABNF=RFC5234}}

# Proxied UDP Binding Mechanism {#mechanism}

In unextended UDP Proxying requests, the target host is encoded in the HTTP
request path or query. For Bound UDP Proxying, the target is either conveyed in
each HTTP Datagram (see {{uncomp-format}}), or registered via capsules and then
compressed (see {{comp-format}}).

When performing URI Template Expansion of the UDP Proxying template (see
{{Section 3 of CONNECT-UDP}}), the client sets both the target_host and the
target_port variables to the '*' character (ASCII character 0x2A).

When sending the UDP Proxying request to the proxy, the client adds the
"Connect-UDP-Bind" header field to identify it as such. If the proxy accepts
the CONNECT UDP Bind request, it adds the allocated public IP:port tuples for
the client to the response; see {{addr-hdr}}.

Endpoints exchange COMPRESSION_ASSIGN capsules in order to establish which IP a
given context ID corresponds to. The context ID can correspond to both
compressed and uncompressed payloads to/from any target and are configured as
defined in {{compression}}.

# Context ID {#contextid}

This extension leverages context IDs (see {{Section 4 of CONNECT-UDP}}) to
compress the target IP address and port when encoding datagrams on the wire.
Endpoints start by registering a context ID and the IP/ports it's associated
with by sending a COMPRESSION_ASSIGN capsule to their peer. The peer will then
echo that capsule to indicate it's received it and estabished its own mapping.
From then on, both endpoints are aware of the context ID and can send
compressed datagrams. Later, any endpoint can decide to close the compression
context by sending a COMPRESSION_CLOSE capsule. Endpoints MUST NOT send two
COMPRESSION_ASSIGN capsules with the same context ID. If a recipient detects
a repeated context ID, it MUST consider the capsule as malformed.

The context ID 0 was reserved by unextended connect-udp and is not used by this
extension. Once an endpoint has ascertained that the peer supports this
extension (see {{hdr}}), the endpoint MUST NOT send any datagrams with context
ID set to 0, and MUST silently drop any received datagrams with context ID set
to 0.

As mandated in {{Section 4 of CONNECT-UDP}}, clients will allocate even context
IDs while proxies will allocate odd ones. They MAY pre-emptively use Context
IDs not yet acknowledged by the other party, knowing that those packets can be
lost since the COMPRESSION_ASSIGN request receiving proxy or client is not
guaranteed to be ready to accept payloads until a COMPRESSION_ASSIGN response
is echoed back.

# Uncompressed Operation {#uncompressed}

If the client wishes to send or receive uncompressed datagrams, it MUST first
exchange the COMPRESSION_ASSIGN capsule (see {{capsuleassignformat}}) with the
proxy with an unused Context ID defined in {{contextid}} with the IP Version
set to zero. Only a single uncompressed context MUST be requested at a time. If
the proxy receives a second uncompressed context COMPRESSION_ASSIGN capsule, it MUST be
considered malformed. Only the client can request uncompressed contexts and if
the proxy attempts to request uncompressed contexts, the client MUST consider
the COMPRESSION_ASSIGN capsule it received malformed.

When HTTP Datagrams {{!HTTP-DGRAM=RFC9297}} are associated with a Bound UDP
Proxying request, the format of their UDP Proxying Payload field (see {{Section
5 of CONNECT-UDP}}) is defined by {{dgram-format}} when uncompressed; every
datagram carries addressing information.

## Uncompressed Payload Format {#uncomp-format}

~~~
Uncompressed Bound UDP Proxying Payload {
  IP Version (8),
  IP Address (32..128),
  UDP Port (16),
  UDP Payload (..),
}
~~~
{: #dgram-format title="Uncompressed Bound UDP Proxying HTTP Datagram Format"}

It contains the following fields:

IP Version:

: The IP Version of the following IP Address field. MUST be 4 or 6.

IP Address:

: The IP Address of this proxied UDP packet. When sent from client to proxy,
this is the target host to which the proxy will send this UDP payload. When
sent from proxy to client, this represents the source IP address of the UDP
packet received by the proxy. This field has a length of 32 bits when the
corresponding IP Version field value is 4, and 128 when the IP Version is 6.

UDP Port:

: The UDP Port of this proxied UDP packet in network byte order. When sent from
client to proxy, this is the target port to which the proxy will send this UDP
payload. When sent from proxy to client, this represents the source UDP port of
the UDP packet received by the proxy.

UDP Payload:

: The unmodified UDP Payload of this proxied UDP packet (referred to as "data
octets" in {{UDP}}).


## Restricting IPs {#restrictingips}

If an uncompressed Context ID was set (via {{uncompressed}}), the client MAY at
any point request the proxy reject all traffic from uncompressed targets by
using COMPRESSION_CLOSE (see {{compressionclose}}) on said Context ID. Then the
proxy effectively acts as a firewall against unwanted or unknown IPs.

# Compressed Operation {#compression}

Endpoints MAY choose to compress the IP and port information per datagram for a
given target using Context IDs. In that case, the endpoint sends a
COMPRESSION_ASSIGN capsule (see {{capsuleassignformat}}) with the target
information it wishes to compress and its peer responds with either a
COMPRESSION_ASSIGN capsule if it accepts the compression request, or a
COMPRESSION_CLOSE with the context ID (see {{capsulecloseformat}}) if it
doesn't wish to support compression for the given Context ID (For example, due
to the memory cost of establishing a list of mappings per target per client).
If the compression was rejected, the client and proxy will instead use an
uncompressed context ID (See {{uncompressed}}) to exhange UDP payloads for the
given target, if those have been enabled. Only one Context ID MUST be used per
IP-port tuple. If both client and server each negotiate a Context ID for the
same tuple, the server MUST accept the client's request and the client MUST
reject or close the server's context ID by sending a COMPRESSION_CLOSE. If
a peer attempts to allocate another Context ID for a tuple which already has
an active context ID previously requested by the same peer, this
COMPRESSION_ASSIGN capsule MUST be considered malformed.

## Compression Mapping {#mappings}

When an endpoint receives a COMPRESSION_ASSIGN capsule with a non-zero IP
length, it MUST decide whether to accept or reject the compression mapping:

* if it accepts the mapping, first the receiver MUST save the mapping from
  context ID to address and port. Second, the receiver MUST echo an identical
  COMPRESSION_ASSIGN capsule back to its peer.

* if it rejects the mapping, the receiver MUST respond by sending a
  COMPRESSION_CLOSE capsule with the context ID set to the one from the
  received COMPRESSION_ASSIGN capsule.

The endpoint MAY choose to close any context that it registered or was
registered with it respectively using COMPRESSION_CLOSE (For example when a
mapping is unused for a long time). Another potential use is {{restrictingips}}.

## Compressed Payload Format {#comp-format}

When HTTP Datagrams {{!HTTP-DGRAM=RFC9297}} are associated with this Bound UDP
Proxying request, the format of their UDP Proxying Payload field (see {{Section
5 of CONNECT-UDP}}) is defined by {{dgram-format}} when the context ID is set
to one previously registered for compressed payloads. (See {{contextid}} for
compressed and uncompressed assignments.)

~~~
Compressed Bound UDP Proxying Payload {
  UDP Payload (..),
}
~~~
{: #dgram-format-compressed title="Compressed Bound UDP Proxying HTTP
Datagram Format"}

It contains the following fields:

UDP Payload:

: The unmodified UDP Payload of this proxied UDP packet (referred to as "data
octets" in {{UDP}}).


# Capsules {#capsules}

This document defines new capsule types that deal with registering context IDs.

## The COMPRESSION_ASSIGN capsule {#compressionassign}

The Compression Assign capsule has two purposes. Either to request the
assignment of a Context ID (see {{contextid}}) to a corresponding target
IP:Port. Or to accept a COMPRESSION_ASSIGN request from the other party.

~~~
Capsule {
  Type COMPRESSION_ASSIGN,
  Length (i),
  Context ID (i),
  IP Version (8),
  [IP Address (32..128)],
  [UDP Port (16)],
}
~~~
{: #capsuleassignformat title="Compression Assign Capsule Format"}

The IP Length, Address and Port fields in {{capsuleassignformat}} are the same
as those defined in {{uncomp-format}}.

When the IP Version is set to 0, the IP Address and UDP Port fields are
omitted. This allows registering an uncompressed Context ID, as described in
{{contextid}}.

## The COMPRESSION_CLOSE capsule {#compressionclose}

The Compression Close capsule serves two purposes. As a response to reject a
COMPRESSION_ASSIGN request and to close or to clean up any existing compression
mappings. Once an endpoint has either sent or received a COMPRESSION_CLOSE for
a given context ID, it MUST NOT send any further datagrams with that Context ID.

~~~
Capsule {
  Type COMPRESSION_CLOSE,
  Length (i),
  Context ID (i),
}
~~~
{: #capsulecloseformat title="Compression Close Capsule Format"}

## Symmetry

As mandated in {{Section 4 of CONNECT-UDP}}, clients can only allocate even
context IDs, while proxies can only allocate odd ones. This makes the
registration capsules above unambiguous. For example, if a client receives a
COMPRESSION_ASSIGN capsule with an even context ID, it knows that this has to
be an echo of a capsule it already sent.

# The Connect-UDP-Bind Header Field {#hdr}

The "Connect-UDP-Bind" header field’s value is a Boolean Structured Field set
to true. Clients and proxy both indicate support for this extension by sending
the Connect-UDP-Bind header field with a value of ?1. Once an endpoint has both
sent and received the Connect-UDP-Bind header field set to true, this extension
is enabled. Any other value type MUST be handled as if the field were not
present by the recipients (for example, if this field is defined multiple
times, its type becomes a List and therefore is to be ignored). This document
does not define any parameters for the Connect-UDP-Bind header field value, but
future documents might define parameters. Receivers MUST ignore unknown
parameters.

# The Proxy-Public-Address Response Header Field {#addr-hdr}

Upon accepting the request, the proxy MUST select at least one public IP
address to bind. The proxy MAY assign more addresses. For each selected
address, it MUST select an open port to bind to this request. From then and
until the tunnel is closed, the proxy SHALL send packets received on these
IP-port tuples to the client. The proxy MUST communicate the selected addresses
and ports to the client using the "Proxy-Public-Address" header. The header is
defined as a List of IP-Port-tuples. The format of the tuple is defined using
IP-literal, IPv4address, IPv6address and port from {{Section 3.2 of
!URI=RFC3986}}.

~~~
ip-port-tuple = ( IP-literal / IPv4address ) ":" port
~~~
{: #target-format title="Proxy Address Format"}

When a single IP-Port tuple is provided in the Proxy-Public-Address field, the
proxy MUST use the same public IP and Port for the remainder of the connection.
When multiple tuples are provided, maintaining address stability per address
family is RECOMMENDED.

Note that since the addresses are conveyed in HTTP response headers, a
subsequent change of addresses on the proxy cannot be conveyed to the client.

# Proxy behavior {#behavior}

After accepting the Connect-UDP Binding proxying request, the proxy uses an
assigned IP:port to transmit UDP payloads received from the client to the
target IP Address and UDP Port specified in each binding Datagram Payload
received from the client. The proxy uses the same ports to listen for UDP
packets from any authorized target and encapsulates the packets in the Binding
Datagram Payload format, and forwards it to the client if a corresponding
Context ID mapping exists for the target.

If the proxy receives UDP payloads that don't correspond to any mapping i.e. no
compression for the given target was ever established and a mapping for
uncompressed or any target is missing, the proxy will either drop the datagram
or temporarily buffer it (see {{Section 5 of CONNECT-UDP}}).

# Security Considerations

The security considerations described in {{Section 7 of CONNECT-UDP}} also
apply here. Since TURN can be run over this mechanism, implementors should
review the security considerations in {{Section 21 of ?TURN=RFC8656}}.

Since unextended UDP Proxying requests carry the target as part of the request,
the proxy can protect unauthorized targets by rejecting requests before
creating the tunnel, and communicate the rejection reason in response header
fields. The uncompressed context allows transporting datagrams to and from any
target. Clients that keep the uncompressed context open need to be able to
receive from all targets. If the UDP proxy would reject unextended UDP proxying
requests to some targets (as recommended in {{Section 7 of CONNECT-UDP}}), then
for bound UDP proxying requests where the uncompressed context is open, the
UDP proxy needs to perform checks on the target of each uncompressed context
datagram it receives.

Note that if the compression response (COMPRESSION_ASSIGN OR COMPRESSION_CLOSE)
cannot be immediately sent due to flow or congestion control, an upper limit on
how many compression responses the endpoint is willing to buffer MUST be set to
prevent memory exhaustion. The proxy MAY close the connection if such
conditions occur.

# IANA Considerations

This document will request IANA to register the following entry in the "HTTP
Field Name" registry maintained at
<[](https://www.iana.org/assignments/http-fields)>:

: Connect-UDP-Bind

Template:
: None

Status:
: provisional (permanent if this document is approved)

Reference:
: This document

Comments:

: None
{: spacing="compact"}


This document also requests IANA to register the following new items to the
"HTTP Capsule Types" registry maintained at
<[](https://www.iana.org/assignments/masque)>:

|   Value    |    Capsule Type    |
|:-----------|:-------------------|
| 0x1C0FE323 | COMPRESSION_ASSIGN |
| 0x1C0FE324 | COMPRESSION_CLOSE  |
{: #iana-capsules-table title="New Capsules"}

All of these new entries use the following values for these fields:

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
"https://example.org/.well-known/masque/udp/{target_host}/{target_port}/"
and listens for traffic on the proxy, eventually decides that it no
longer wants to listen for connections from new targets, and limits
its communication with only 203.0.113.11:4321 and no other UDP target.

~~~
 Client                                             Server

 STREAM(44): HEADERS            -------->
   :method = CONNECT
   :protocol = connect-udp
   :scheme = https
   :path = /.well-known/masque/udp/*/*/
   :authority = proxy.example.org
   connect-udp-bind = ?1
   capsule-protocol = ?1

            <--------  STREAM(44): HEADERS
                         :status = 200
                         connect-udp-bind = ?1
                         capsule-protocol = ?1
                         proxy-public-address = 192.0.2.45:54321,  \
                                            [2001:db8::1234]:54321

/* Request Context ID 2 to be used for uncompressed UDP payloads
 from/to any target */

 CAPSULE                       -------->
   Type = COMPRESSION_ASSIGN
   Context ID = 2
   IP Version = 0


/* Proxy confirms registration. */

            <-------- CAPSULE
                        Type = COMPRESSION_ASSIGN
                        Context ID = 2
                        IP Version = 0

/* Target talks to Client using the uncompressed context */

            <--------  DATAGRAM
                         Quarter Stream ID = 11
                         Context ID = 2
                         IP Version = 4
                         IP Address = 192.0.2.42
                         UDP Port = 1234
                         UDP Payload = Encapsulated UDP Payload

/ * Client responds on the same uncompressed context */

 DATAGRAM                       -------->
   Quarter Stream ID = 11
   Context ID = 2
   IP Version = 4
   IP Address = 192.0.2.42
   UDP Port = 1234
   UDP Payload = Encapsulated UDP Payload

/* Another target talks to Client using the uncompressed context */
            <--------  DATAGRAM
                         Quarter Stream ID = 11
                         Context ID = 2
                         IP Version = 4
                         IP Address = 203.0.113.11
                         UDP Port = 4321
                         UDP Payload = Encapsulated UDP Payload

/ * Client responds on the same uncompressed context */

 DATAGRAM                       -------->
   Quarter Stream ID = 11
   Context ID = 2
   IP Version = 4
   IP Address = 203.0.113.11
   UDP Port = 4321
   UDP Payload = Encapsulated UDP Payload

/* Register 203.0.113.11:4321 to compress it in the future */
 CAPSULE                       -------->
   Type = COMPRESSION_ASSIGN
   Context ID = 4
   IP Version = 4
   IP Address = 203.0.113.11
   UDP Port = 4321


/* Proxy confirms registration.*/
            <-------- CAPSULE
                        Type = COMPRESSION_ASSIGN
                        Context ID = 4
                        IP Version = 4
                        IP Address = 203.0.113.11
                        UDP Port = 4321

/* Omit IP and Port for future packets intended for*/
/* 203.0.113.11:4321 hereon */
 DATAGRAM                       -------->
   Context ID = 4
   UDP Payload = Encapsulated UDP Payload

            <--------  DATAGRAM
                        Context ID = 4
                        UDP Payload = Encapsulated UDP Payload

/* Request packets without a corresponding compressed Context */
/* to be dropped by closing the uncompressed Context */
 CAPSULE                       -------->
   Type = COMPRESSION_CLOSE
   Context ID = 2


/* Proxy confirms unmapped IP rejection. */
            <-------- CAPSULE
                        Type = COMPRESSION_CLOSE
                        Context ID = 2

/* Context ID 4 = 203.0.113.11:4321 traffic is accepted, */
/* And the rest is dropped at the proxy */


~~~

# Comparison with CONNECT-IP

While the use-cases described in {{intro}} could be supported using IP Proxying
in HTTP {{?CONNECT-IP=RFC9484}}, it would require that every HTTP Datagram
carries a complete IP header. This would lead to both inefficiencies in the
wire encoding and reduction in available Maximum Transmission Unit (MTU).
Furthermore, Web browsers would need to support IPv4 and IPv6 header
generation, parsing, validation and error handling.

# Acknowledgments
{:numbered="false"}

This proposal is the result of many conversations with MASQUE working group
participants.

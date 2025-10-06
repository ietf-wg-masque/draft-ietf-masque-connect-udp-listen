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
behaviors from {{!ABNF=RFC5234}}.

# Proxied UDP Binding Mechanism {#mechanism}

In unextended UDP Proxying requests, the target host is encoded in the HTTP
request path or query. For Bound UDP Proxying, the target is either conveyed in
each HTTP Datagram (see {{fmt-dgram-uncomp}}), or registered via capsules and
then compressed (see {{fmt-capsule-assign}}).

When performing URI Template Expansion of the UDP Proxying template (see
{{Section 3 of CONNECT-UDP}}), the client follows the same template as
CONNECT-UDP and sets the "target_host" and the "target_port" variables
to one of its targets. It adds the connect-udp-bind header as specified in
{{hdr}} to request bind. If the proxy supports CONNECT-UDP Bind, it returns
the connect-udp-bind response header value set to true.

When target_host and target_port are set to a valid target, the client is
requesting CONNECT-UDP Bind but would accept fallback to unextended
CONNECT-UDP to that target. If the client doesn't have a specific target, or if
it wants CONNECT-UDP bind without fallback, it sets both the "target_host" and
the "target_port" variables to the '\*' character (ASCII character 0x2A). Note
that the '\*' character MUST be percent-encoded before sending, per {{Section
3.2.2 of !TEMPLATE=RFC6570}}.


# Context Identifiers {#contextid}

As with unextended UDP proxying, the semantics of HTTP Datagrams are conveyed
by Context IDs (see {{Section 4 of CONNECT-UDP}}). Endpoints first allocate a
new Context ID (per {{CONNECT-UDP}}, clients allocate even Context IDs while
proxies allocate odd ones), and then use the COMPRESSION_ASSIGN capsule (see
{{capsule-assign}}) to convey the semantics of the new Context ID to their
peer. This process is known as registering the Context ID.

Each Context ID can have either compressed or uncompressed semantics. The
uncompressed variant encodes the target IP and port into each HTTP Datagram.
Conversely, the compressed variant exchanges the target IP and port once in the
capsule during registration, and then relies on shared state to map from the
Context ID to the IP and port.

Context ID 0 was reserved by unextended connect-udp to represent UDP
payloads sent to and from the "target_host" and "target_port" from the
URI template. When the mechanism from this document is in use:
* if the "target_host" and "target_port" variables are set to `\*`, then
context ID 0 MUST NOT be used in HTTP Datagrams.
* otherwise, HTTP Datagrams with context ID 0 have the same semantics
as in unextended connect-udp.


## The COMPRESSION_ASSIGN capsule {#capsule-assign}

The Compression Assign capsule is used to register the semantics of a Context
ID. It has the following format:

~~~
COMPRESSION_ASSIGN Capsule {
  Type (i) = 0x1C0FE323,
  Length (i),
  Context ID (i),
  IP Version (8),
  [IP Address (32..128)],
  [UDP Port (16)],
}
~~~
{: #fmt-capsule-assign title="Compression Assign Capsule Format"}

It contains the following fields:

IP Version:

: The IP Version of the following IP Address field. MUST be 0, 4 or 6. Setting
this to zero indicates that this capsule registers an uncompressed context.
Otherwise, the capsule registers a compressed context for the IP address and
UDP port it carries.

IP Address:

: The IP Address of this context. This field is omitted if the IP Version field
is set to 0. Otherwise, it has a length of 32 bits when the corresponding IP
Version field value is 4, and 128 when the IP Version is 6.

UDP Port:

: The UDP Port of this context, in network byte order. This field is omitted if
the IP Version field is set to 0.

When an endpoint receives a COMPRESSION_ASSIGN capsule, it MUST either accept
or reject the corresponding registration:

* if it accepts the registration, first the receiver MUST save the mapping from
  Context ID to address and port (or save the fact that this context ID is
  uncompressed). Second, the receiver MUST echo an identical COMPRESSION_ASSIGN
  capsule back to its peer, to indicate it has accepted the registration.

* if it rejects the registration, the receiver MUST respond by sending a
  COMPRESSION_CLOSE capsule with the Context ID set to the one from the
  received COMPRESSION_ASSIGN capsule.

As mandated in {{Section 4 of CONNECT-UDP}}, clients can only allocate even
Context IDs, while proxies can only allocate odd ones. This makes the
registration capsules from this document unambiguous. For example, if a client
receives a COMPRESSION_ASSIGN capsule with an even Context ID, that has to be
an echo of a capsule that the client initially sent, indicating that the proxy
accepted the registration. Since the value 0 was reserved by unextended
connect-udp, the Context ID value of COMPRESSION_ASSIGN can never be zero.

Endpoints MUST NOT send two COMPRESSION_ASSIGN capsules with the same Context
ID. If a recipient detects a repeated Context ID, it MUST treat the capsule as
malformed. Receipt of a malformed capsule MUST be treated as an error
processing the Capsule Protocol, as defined in {{Section 3.3 of
!HTTP-DGRAM=RFC9297}}.

If the uncompressed context is closed, the proxy MUST NOT open new compressed
contexts. In such a case, the proxy opening contexts results in tuples not
desired by the client reaching it thereby nullifying the IP restriction
property of uncompressed compression close as described in
{{restricting-ips}}.

Only one Context ID can be used per IP-port tuple. If an endpoint detects that
both it and its peer have opened a Context ID for the same tuple, the endpoint
MUST close the Context ID that was opened by the proxy. If an endpoint receives
a COMPRESSION_ASSIGN capsule whose tuple matches another open Context ID, it
MUST treat the capsule as malformed.

Endpoints MAY pre-emptively use Context IDs not yet acknowledged by the peer,
knowing that those HTTP Datagrams can be dropped if they arrive before the
corresponding COMPRESSION_ASSIGN capsule, or if the peer rejects the
registration.

## The COMPRESSION_CLOSE capsule {#capsule-close}

The Compression Close capsule serves two purposes. It can be sent as a direct
response to a received COMPRESSION_ASSIGN capsule, to indicate that the
registration was rejected. It can also be sent later to indicate the closure of
a previously assigned registration.

~~~
COMPRESSION_CLOSE Capsule {
  Type (i) = 0x1C0FE324,
  Length (i),
  Context ID (i),
}
~~~
{: #fmt-capsule-close title="Compression Close Capsule Format"}

Once an endpoint has either sent or received a COMPRESSION_CLOSE for a given
Context ID, it MUST NOT send any further datagrams with that Context ID.
Since the value 0 was reserved by unextended connect-udp, the Context ID
value of COMPRESSION_CLOSE can never be zero.

Endpoints MAY close any context regardless of which endpoint registered it.
This is useful for example, when a mapping is unused for a long time. Another
potential use is restricting some targets (see {{restricting-ips}}).

Once a registration is closed, endpoints can instead use an uncompressed
Context ID to exchange UDP payloads for the given target, if such a context has
been registered (see {{uncompressed}}).

# Uncompressed Operation {#uncompressed}

If the client wishes to send or receive uncompressed datagrams, it MUST first
send a COMPRESSION_ASSIGN capsule (see {{fmt-capsule-assign}}) to the proxy
with the IP Version set to zero. This registers the Context ID as being
uncompressed semantics: all HTTP Datagrams with this Context ID have the
following format:

~~~
Uncompressed Bound UDP Proxying Payload {
  IP Version (8),
  IP Address (32..128),
  UDP Port (16),
  UDP Payload (..),
}
~~~
{: #fmt-dgram-uncomp title="Uncompressed Bound UDP Proxying HTTP Datagram Format"}

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

A client MUST NOT open an uncompressed Context ID if one is already open. If a
server receives a request to open an uncompressed Context ID and it already has
one open, then the server MUST treat the second capsule as malformed. Note that
it's possible for the client to close the uncompressed context and reopen it
later with a different Context ID, as long as there aren't two uncompressed
contexts open at the same time. Only the client can request uncompressed
contexts. If a client receives a COMPRESSION_ASSIGN capsule with the IP Version
set to 0, it MUST treat it as malformed.

# Compressed Operation {#compressed-operation}

Endpoints MAY choose to compress the IP and port information per datagram for a
given target using Context IDs. This is accomplished by registering a
compressed Context ID using the COMPRESSION_ASSIGN capsule (see
{{fmt-capsule-assign}}).

If the Context ID in an HTTP Datagram matches one previously registered for
compressed operation, the rest of the HTTP Datagram represents the UDP payload:

~~~
Compressed Bound UDP Proxying Payload {
  UDP Payload (..),
}
~~~
{: #fmt-dgram-comp title="Compressed Bound UDP Proxying HTTP Datagram Format"}

It contains the following field:

UDP Payload:

: The unmodified UDP Payload of this proxied UDP packet (referred to as "data
octets" in {{UDP}}).

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
and ports to the client using the "Proxy-Public-Address" header field. The
header field is defined as a List of ip-port-tuples. The format of the tuple is
defined using IP-literal, IPv4address, and port from {{Section 3.2 of
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

If the proxy only shares IP addresses from a single address family, it
indicates that the proxy only supports that family. The client SHOULD NOT
attempt to register compressed contexts or send uncompressed datagrams
intended for targets whose ip address families were not indicated via the
IP addresses listed in the Proxy-Public-Address header field, as the proxy
will drop said datagrams or capsules.

# Proxy behavior {#behavior}

After accepting the Connect-UDP Binding proxying request, the proxy uses an
assigned IP address and port to transmit UDP payloads received from the client
to the target IP Address and UDP Port specified in each HTTP Datagram received
from the client. The proxy uses the same ports to listen for UDP packets from
any authorized target and forwards them to the client by encapsulating them in
HTTP Datagrams, using the corresponding Context ID.

If the proxy receives UDP payloads that don't correspond to any registration
(i.e., no compression for the given target was ever established and there is no
uncompressed registration), the proxy will either drop the datagram or
temporarily buffer it (see {{Section 5 of CONNECT-UDP}}).

## Restricting IPs {#restricting-ips}

If a client does not wish to receive datagrams from unknown senders, it can
close the uncompressed registration (or not open it in the first place). In
that scenario, the proxy effectively acts as a firewall against unwanted or
unknown IPs.

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
for bound UDP proxying requests where the uncompressed context is open, the UDP
proxy needs to perform checks on the target of each uncompressed context
datagram it receives.

Note that if the compression response (COMPRESSION_ASSIGN OR COMPRESSION_CLOSE)
cannot be immediately sent due to flow or congestion control, an upper limit on
how many compression responses the endpoint is willing to buffer MUST be set to
prevent memory exhaustion. The proxy MUST abort the request stream if this
limit is reached.

# Operational Considerations

When moving traffic between uncompressed and compressed contexts, the effective
MTU will change. This can hinder Datagram Packetization Layer PMTU Discovery
(DPLPMTUD) between the client and the target {{?DPLPMTUD=RFC8899}}.
To avoid that, if an endpoint intends to use compression, it SHOULD request it
as early as possible.

# IANA Considerations

## HTTP Fields {#iana-fields}

This document will request IANA to register the following new items in the
"HTTP Field Name" registry maintained at
<[](https://www.iana.org/assignments/http-fields)>:

|      Field Name      | Structured Type |
|:---------------------|:----------------|
|   Connect-UDP-Bind   |      Item       |
| Proxy-Public-Address |      List       |
{: #iana-fields-table title="New Fields"}

All of these new entries use the following values for these fields:

Status:
: provisional (permanent if this document is approved)

Reference:
: This document

Comments:
: None
{: spacing="compact"}

## Capsules {#iana-capsules}

This document will request IANA to register the following new items to the
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

Change Controller:
: IETF

Contact:
: MASQUE Working Group <masque@ietf.org>

Notes:
: None
{: spacing="compact"}

Note that these values will be replaced by lower ones prior to publication.

--- back

# Example

In the example below, the client is configured with URI Template
"https://example.org/.well-known/masque/udp/{target_host}/{target_port}/" and
listens for traffic on the proxy, eventually decides that it no longer wants to
listen for connections from new targets, and limits its communication with only
203.0.113.11:4321 and no other UDP target.

~~~
 Client                                             Server

 STREAM(44): HEADERS            -------->
   :method = CONNECT
   :protocol = connect-udp
   :scheme = https
   :path = /.well-known/masque/udp/%2A/%2A/
   :authority = proxy.example.org
   connect-udp-bind = ?1
   capsule-protocol = ?1

            <--------  STREAM(44): HEADERS
                         :status = 200
                         connect-udp-bind = ?1
                         capsule-protocol = ?1
                         proxy-public-address = 192.0.2.45:54321,  \
                                            [2001:db8::1234]:54321

/* Register Context ID 2 to be used for uncompressed UDP payloads
 to/from any target */

 CAPSULE                       -------->
   Type = COMPRESSION_ASSIGN
   Context ID = 2
   IP Version = 0


/* Proxy confirms registration */

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

/* Client responds on the same uncompressed context */

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

/* Client responds on the same uncompressed context */

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


/* Proxy confirms registration */

            <-------- CAPSULE
                        Type = COMPRESSION_ASSIGN
                        Context ID = 4
                        IP Version = 4
                        IP Address = 203.0.113.11
                        UDP Port = 4321

/* Omit IP and Port for future packets intended for */
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
participants. In particular, the authors would like to thank {{{Marius
Kleidl}}}, {{{Tommy Pauly}}}, {{{Lucas Pardue}}}, {{{Ben Schwartz}}}, and
{{{Magnus Westerlund}}} for their reviews.

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
from {{!QUIC=RFC9000}}. This document uses the terms Integer, Boolean and List from
{{Section 3 of !STRUCTURED-FIELDS=RFC8941}} to specify syntax and parsing.


# Proxied UDP Binding Mechanism {#mechanism}

In unextended UDP Proxying requests, the target host is encoded in the HTTP
request path or query. For Bound UDP Proxying, the target is either conveyed in each
HTTP Datagram (see {{format}}), or registered via capsules and then compressed
(see {{contextid}}).

When performing URI Template Expansion of the UDP Proxying template (see
{{Section 3 of CONNECT-UDP}}), the client sets both the target_host and the
target_port variables to the '*' character (ASCII character 0x2A).

This extension leverages context IDs (see Section 4 of CONNECT-UDP) to compress
the target IP address and port when encoding datagrams on the wire. Either
endpoint can register a context ID and the IP/ports it's associated with by
sending a COMPRESSION_ASSIGN capsule to its peer. The peer will then echo that
capsule to indicate that it has been received and accepted. From then on, both endpoints are aware of
the context ID and can send compressed datagrams. Later, any endpoint can
decide to close the compression context by sending a COMPRESSION_CLOSE capsule.

When sending the UDP Proxying request to the proxy, the client adds
the "connect-udp-bind" header field to identify it as such. Both client and proxy can negotiate even and odd numbered context IDs to send UDP payloads to each other.

The client and the proxy exchange COMPRESSION_ASSIGN capsules in order to
establish which IP a given context ID corresponds to. The context ID can
correspond to both compressed and uncompressed payloads to/from any target and
are configured as defined in {{compression}}.

# HTTP Datagram Payload Format {#format}

When HTTP Datagrams {{!HTTP-DGRAM=RFC9297}} associated with this Bound UDP
Proxying request contain the Connect-UDP-Bind header field,
the format of their UDP Proxying Payload field (see {{Section 5 of
CONNECT-UDP}}) is defined by {{dgram-format}} when context ID is set to be used
used for uncompressed connect-udp bind and {{dgram-format-compressed}} when
context ID is set to one previously registered for compressed payloads.
(See {{contextid}} for compressed and uncompressed assignments.)

~~~ ascii-art
Bound UDP Uncompressed Payload {
  IP Version (8),
  IP Address (32..128),
  UDP Port (16),
  UDP Payload (..),
}
~~~
{: #dgram-format title="Uncompressed Bound UDP Proxying HTTP Datagram Format"}

~~~ ascii-art
Bound UDP Proxying Compressed Payload {
  UDP Payload (..),
}
~~~
{: #dgram-format-compressed title="Compressed Bound UDP Proxying HTTP Datagram Format"}

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

# Context ID {#contextid}

This extension leverages context IDs (see {{Section 4 of CONNECT-UDP}}) to compress the target IP address and port when encoding datagrams on the wire. Either endpoint can register a context ID and the IP/ports it's associated with by sending a COMPRESSION_ASSIGN capsule to its peer. The peer will then echo that capsule to indicate it's received it. From then on, both endpoints are aware of the context ID and can send compressed datagrams. Later, any endpoint can decide to close the compression context by sending a COMPRESSION_CLOSE capsule.

The context ID 0 was reserved by unextended connect-udp and is not used by this extension.
Once an endpoint has ascertained that the peer supports this extension, the endpoint MUST NOT
send any datagrams with context ID set to 0, and MUST silently drop any received datagrams with
context ID set to 0.

As mandated in {{Section 4 of CONNECT-UDP}}, clients will allocate even context IDs
while proxies will allocate odd ones.
They MAY pre-emptively use Context IDs not yet acknowledged by the other party, knowing that those packets MAY be lost since the COMPRESSION_ASSIGN request receiving proxy
or client is not guaranteed to be ready to accept payloads until a COMPRESSION_ASSIGN
response is echoed back.

## Address Compression {#compression}

The client and the proxy MAY choose to compress the IP and port information
per datagram for a given target against the Context ID.
In such a case, the client or the proxy sends a COMPRESSION_ASSIGN capsule
(see {{capsuleassignformat}}) with the target information (see
{{targetmappingformat}}) it wishes to compress and the other party (proxy or
client respectively) echoes back with either a COMPRESSION_ASSIGN capsule
if it accepts the compression request, or a COMPRESSION_CLOSE with the context
ID (see {{capsulecloseformat}}) if it doesn't wish to support  compression for
the given Context ID (For example, due to considerable memory requirements of
establishing  a list of mappings per target per client). If the compression was
rejected, the client and proxy MUST use an uncompressed context ID (See {{uncompressed}}) to exhange
UDP payloads for the given target.

### Uncompressed datagrams {#uncompressed}

If the client wishes to allocate a Context ID for uncompressed packets,
it MUST first exchange the COMPRESSION_ASSIGN capsule (see {{capsuleassignformat}})
with the proxy with an unused Context ID defined in {{contextid}} with
the IP Length set to zero.


### Compression Mapping {#mappings}

When an endpoint receives a COMPRESSION_ASSIGN capsule with a non-zero IP length, it MUST decide whether to accept or reject the compression mapping:

if it accepts the mapping, first the receiver MUST save the mapping from context ID to address and port. Second, the receiver MUST echo an identical COMPRESSION_ASSIGN capsule back to its peer.

if it rejects the mapping, the receiver MUST respond by sending a COMPRESSION_CLOSE capsule with the context ID set to the one from the received COMPRESSION_ASSIGN capsule

The client or proxy MAY choose to close any context contexts that it registered
or was registered with it respectively using COMPRESSION_CLOSE
(For example when a mapping is unused for a long time). Another potential use is
{{restrictingips}}.


## Restricting IPs {#restrictingips}

If an uncompressed Context ID was set (via {{uncompressed}}), the client MAY at any point request the proxy reject all traffic from uncompressed
targets by using COMPRESSION_CLOSE (see {{compressionclose}}) on said Context ID.
targets effectively acting as a firewall against unwanted or unknown IPs.


## Capsules {#capsules}
The Listener capsule types are defined as follows:

### The COMPRESSION_ASSIGN capsule {#compressionassign}

The Compression Assign capsule has two purposes. Either to request the assignment of a Context ID (see {{contextid}}) to a corresponding target IP:Port. Or to accept a COMPRESSION_ASSIGN request from the other party.

~~~ ascii-art
Capsule {
  Type COMPRESSION_ASSIGN (0x1F1F1F1F),
  Length (i),
  Target Information,
}
~~~
{: #capsuleassignformat title="Compression Assign Capsule Format"}

~~~ ascii-art
Target Information {
  Context ID (i),
  IP Version (8),
  IP Address (32..128),
  UDP Port (16),
}
~~~
{: #targetmappingformat title="Target Information Format"}

The IP Length, Address and Port fields in {{targetmappingformat}} are the
same as those defined in {{format}}. However, the IP version can be set
to 0 when allocating an uncompressed Context ID, as defined in {{contextid}}.

### The COMPRESSION_CLOSE capsule {#compressionclose}

The Compression Close capsule serves the following purposes. As a response to reject a COMPRESSION_ASSIGN request and to close or clean up any existing compression mappings. Once a COMPRESSION_CLOSE is sent for a given Context ID, the sending party MAY reject any datagrams received for that Context ID until it is reallocated through a COMPRESSION_ASSIGN exchange.

~~~ ascii-art
Capsule {
  Type COMPRESSION_CLOSE (0x1F1F1F20),
  Length (i),
  Context ID (i),
}
~~~
{: #capsulecloseformat title="Compression Close Capsule Format"}



# The connect-udp-bind Header Field {#hdr}

The "connect-udp-bind" header field’s value is a boolean structured field
set to to true. Any other value type MUST be handled as if the field were not
present by the recipients (for example, if this field is defined multiple times,
its type becomes a List and therefore is to be ignored). This document does not
define any parameters for the Connect-UDP-Bind header field value, but future
documents might define parameters. Receivers MUST ignore unknown parameters.

# Proxy behavior

After accepting the Connect-UDP Binding proxying request, the proxy uses a UDP
port to transmit UDP payloads received from the client to the target IP Address
and UDP Port specified in each binding Datagram Payload received from the
client. The proxy uses the same port to listen for UDP packets from any
authorized target and encapsulates the packets in the Binding Datagram
Payload format, specifying the IP and port of the target and forwards it to
the client.
When the client or proxy send a COMPRESSION_ASSIGN capsule, the proxy or client
respectively either register a mapping from Context ID to the provided target
and port and echo back the capsule or reject. If the IP length was 0,
the Context ID can be used by either party to send uncompressed payloads and
the proxy reads the IP, port information per  packet, as opposed to doing a
lookup in its Compression Mapping.


When COMPRESSION_CLOSE is received from or sent to the client, the proxy and
client forget the context ID, regardless of whether it is compressed or
uncompressed.

If the proxy receives UDP payloads that don't correspond to any mapping i.e.
no compression for the given target was ever established and a mapping for
uncompressed or any target is missing, the proxy simply drops the packet.


# Security Considerations

The security considerations described in {{Section 7 of CONNECT-UDP}} also apply
here. Since TURN can be run over this mechanism, implementors should review the
security considerations in {{Section 21 of ?TURN=RFC8656}}.

Since unextended UDP Proxying requests carry the target as part of the request,
the proxy can protect unauthorized targets by rejecting requests before creating
the tunnel, and communicate the rejection reason in response header fields.
Bound UDP Proxying requests do not have this ability. Therefore, proxies MUST
validate the target on every datagram and MUST NOT forward individual datagrams
with unauthorized targets. Proxies can either silently discard such datagrams or
abort the corresponding request stream.

Note that if the compression response (COMPRESSION_ASSIGN OR COMPRESSION_CLOSE)
cannot be immediately sent due to flow or congestion control, an upper limit on how many compression responses the endpoint is willing to buffer SHOULD be set to prevent DDOS-ing. The proxy MAY
close the connection if such conditions occur.

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


This document also requests IANA to register the following new "HTTP Capsule Types" maintained at
<[](https://www.iana.org/assignments/masque)>:

Value:
: 0x1F1F1F1F

Capsule Type:
: COMPRESSION_ASSIGN

Status:
: provisional (permanent if this document is approved)

Reference:
: This document

Comments:

: None
{: spacing="compact"}

Value:
: 0x1F1F1F20

Capsule Type:
: COMPRESSION_CLOSE

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
wishes to use WebRTC with another browser over a Bound UDP Proxying tunnel.
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
   connect-udp-bind = ?1
   capsule-protocol = ?1

            <--------  STREAM(44): HEADERS
                         :status = 200
                         capsule-protocol = ?1

/* Request Context ID 2 to be used for uncompressed UDP payloads
 from/to any target */
 CAPSULE                       -------->
   Type = COMPRESSION_ASSIGN (0x1F1F1F1F)
   Context ID = 2
   IP Version = 0


/*Proxy confirms registration.*/
            <-------- CAPSULE
                        Type = COMPRESSION_ASSIGN (0x1F1F1F1F)
                        Context ID = 2
                        IP Version = 0

 DATAGRAM                       -------->
   Quarter Stream ID = 11
   Context ID = 2
   IP Version = 4
   IP Address = 192.0.2.42
   UDP Port = 1234
   UDP Payload = Encapsulated UDP Payload

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

/* Register 203.0.113.33:1234 to compress it in the future*/
 CAPSULE                       -------->
   Type = COMPRESSION_ASSIGN (0x1F1F1F1F)
   Context ID = 4
   IP Version = 4
   IP Address = 203.0.113.33
   UDP Port = 1234


/*Proxy confirms registration.*/
            <-------- CAPSULE
                        Type = COMPRESSION_ASSIGN (0x1F1F1F1F)
                        Context ID = 4
                        IP Version = 4
                        IP Address = 203.0.113.33
                        UDP Port = 1234

/* Omit IP and Port for future packets intended for*/
/*203.0.113.33:1234 hereon */
 DATAGRAM                       -------->
   Context ID = 4
   UDP Payload = Encapsulated UDP Payload

            <--------  DATAGRAM
                        Context ID = 4
                        UDP Payload = Encapsulated UDP Payload

/* Request packets without a corresponding context to be dropped*/
 CAPSULE                       -------->
   Type = COMPRESSION_CLOSE (0x1F1F1F20)
   Context ID = 2



/* Proxy confirms unmapped IP rejection. */
            <-------- CAPSULE
                        Type = COMPRESSION_CLOSE (0x1F1F1F20)
                        Context ID = 2
/* Proxy drops any packets received on the
bound IP(s):Port */
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

# NAT64, DNS64, and 464XLAT Investigation

Investigated on Windows 11 with read-only diagnostics. No firewall rule or network
configuration was changed.

## Active network

- Active interface: Wi-Fi
- IPv4 address: `10.48.162.252/24`
- IPv4 gateway: `10.48.162.49`
- Global IPv6 addresses:
  - `2401:4900:b370:5b25:ac1c:8b8:5ab:e7e8/128`
  - `2401:4900:b370:5b25:76a3:6b38:7cf2/64`
- IPv6 default route: `::/0` via `fe80::883c:d7ff:fe04:5c54`
- IPv6 route to `2401:4900:b370:5b25::/64` exists.

The global IPv6 addresses and a default IPv6 route show that native IPv6 routing
is available. This does not, by itself, prove which mechanism would serve every
IPv6-only destination.

## DNS64 and RFC 7050

The configured Wi-Fi resolvers were:

- IPv4 DNS: `10.48.162.49`
- IPv6 DNS: `2401:4900:b370:5b25::6e`

Default resolver queries for `ipv4only.arpa` returned:

- A: `192.0.0.170`
- A: `192.0.0.171`
- AAAA: no result

Direct queries through both the current IPv4 and IPv6 Wi-Fi DNS resolvers also
produced no usable synthesized AAAA result.

According to RFC 7050, the lack of DNS64-synthesized AAAA records for
`ipv4only.arpa` means DNS64 synthesis was not observed. It does not prove that
DNS64 or NAT64 is absent. It means the available DNS discovery test was negative.

No possible synthesized IPv6 address containing one of the RFC 7050 IPv4 markers
was found.

## NAT64 prefixes

No route for `64:ff9b::/96` was found.

This does not prove NAT64 is absent. NAT64 implementations may use a
network-specific prefix that is not visible as the well-known `64:ff9b::/96`
prefix. Also, route discovery alone does not identify whether translation is
actually occurring.

## 464XLAT

No CLAT-style Windows adapter or 464XLAT configuration indicator was found.
Teredo was disabled, and no 6to4 adapter was present.

Windows diagnostics available here do not conclusively identify 464XLAT.
Therefore 464XLAT remains `unknown`, not absent.

## Browser measurement implications

DNS64 can create a synthetic AAAA answer for an IPv4-only server. NAT64 can then
translate the IPv6-side connection to IPv4. Such a path is reachable only through
translation and is not native IPv6 delivery to the origin server.

Playwright `Response.server_addr()` shows the remote IPv6 address used in the
browser connection. It does not prove that the address belongs to a native
IPv6-capable origin. It may represent a DNS64-synthesized NAT64 destination.

Additional evidence for native IPv6 would include:

- Direct IPv6 reachability to a server's own globally routable IPv6 address.
- Server-side or packet-capture evidence showing the source and destination are
  native IPv6 rather than a NAT64 translation endpoint.
- An IPv4-only control resource that succeeds through DNS64/NAT64 and a separate
  native IPv6-only resource that remains reachable.
- NAT64 prefix and translation-state evidence from the network operator or router.

## Controlled experiment suitability

The hotspot is potentially suitable for an initial IPv6-only browser experiment
because:

- It has global IPv6 addresses.
- It has an IPv6 default route.
- `curl.exe -6 -I https://example.com` returned HTTP 200.

It is not suitable for claiming native IPv6 unless a controlled dual-stack page
and an actually IPv4-only resource are also tested. DNS64/NAT64 and 464XLAT
remain unresolved, so any translated success must be reported separately.

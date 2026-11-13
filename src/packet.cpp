#include "netsim/packet.hpp"

#include <algorithm>
#include <stdexcept>

namespace netsim {
namespace {
inline std::uint16_t rd16(const std::uint8_t* p) { return static_cast<std::uint16_t>((p[0] << 8) | p[1]); }
inline std::uint32_t rd32(const std::uint8_t* p) {
    return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) | p[3];
}
inline void wr16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v & 0xff);
}
inline void wr32(std::uint8_t* p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>((v >> 16) & 0xff);
    p[2] = static_cast<std::uint8_t>((v >> 8) & 0xff);
    p[3] = static_cast<std::uint8_t>(v & 0xff);
}
}  // namespace

const char* toString(ParseError e) {
    switch (e) {
        case ParseError::None: return "none";
        case ParseError::TooShort: return "too short";
        case ParseError::BadVersion: return "bad version";
        case ParseError::BadHeaderLength: return "bad header length";
        case ParseError::BadTotalLength: return "bad total length";
        case ParseError::BadChecksum: return "bad checksum";
    }
    return "?";
}

std::uint16_t internetChecksum(const std::uint8_t* d, std::size_t len) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < len; i += 2) sum += rd16(d + i);
    if (len & 1) sum += std::uint32_t{d[len - 1]} << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

ParseError parseHeader(const std::uint8_t* d, std::size_t len, IPv4Header& h) {
    if (len < 20) return ParseError::TooShort;
    if ((d[0] >> 4) != 4) return ParseError::BadVersion;
    const std::size_t ihl = d[0] & 0x0f;
    if (ihl < 5 || len < ihl * 4) return ParseError::BadHeaderLength;
    const std::uint16_t total = rd16(d + 2);
    if (total < ihl * 4 || total > len) return ParseError::BadTotalLength;
    if (internetChecksum(d, ihl * 4) != 0) return ParseError::BadChecksum;
    h.version = 4;
    h.ihl = static_cast<std::uint8_t>(ihl);
    h.tos = d[1];
    h.totalLength = total;
    h.id = rd16(d + 4);
    h.flagsFragment = rd16(d + 6);
    h.ttl = d[8];
    h.protocol = d[9];
    h.checksum = rd16(d + 10);
    h.src = rd32(d + 12);
    h.dst = rd32(d + 16);
    return ParseError::None;
}

ParseError parsePacket(const std::vector<std::uint8_t>& bytes, Packet& out) {
    ParseError e = parseHeader(bytes.data(), bytes.size(), out.header);
    if (e != ParseError::None) return e;
    out.payload.assign(bytes.begin() + out.header.ihl * 4, bytes.begin() + out.header.totalLength);
    return ParseError::None;
}

std::vector<std::uint8_t> serialize(const Packet& p) {
    const std::size_t total = 20 + p.payload.size();
    if (total > 0xffff) throw std::length_error("packet too large");
    std::vector<std::uint8_t> b(total, 0);
    b[0] = 0x45;
    b[1] = p.header.tos;
    wr16(&b[2], static_cast<std::uint16_t>(total));
    wr16(&b[4], p.header.id);
    wr16(&b[6], p.header.flagsFragment);
    b[8] = p.header.ttl;
    b[9] = p.header.protocol;
    wr32(&b[12], p.header.src);
    wr32(&b[16], p.header.dst);
    wr16(&b[10], internetChecksum(b.data(), 20));
    std::copy(p.payload.begin(), p.payload.end(), b.begin() + 20);
    return b;
}

std::vector<std::uint8_t> makePacket(IPv4 src, IPv4 dst, std::uint8_t ttl, std::size_t payloadSize,
                                     std::uint8_t protocol) {
    Packet p;
    p.header.src = src;
    p.header.dst = dst;
    p.header.ttl = ttl;
    p.header.protocol = protocol;
    p.payload.resize(payloadSize);
    for (std::size_t i = 0; i < payloadSize; ++i) p.payload[i] = static_cast<std::uint8_t>(i);
    return serialize(p);
}

bool decrementTtl(std::uint8_t* d) {
    if (d[8] == 0) return false;
    --d[8];
    std::uint32_t sum = std::uint32_t{rd16(d + 10)} + 0x0100u;  // RFC 1141
    wr16(d + 10, static_cast<std::uint16_t>(sum + (sum >> 16)));
    return true;
}

}  // namespace netsim

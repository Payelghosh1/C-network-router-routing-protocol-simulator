#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

#include "netsim/ip.hpp"

namespace netsim {

struct IPv4Header {
    std::uint8_t version = 4;
    std::uint8_t ihl = 5;  // header length in 32-bit words
    std::uint8_t tos = 0;
    std::uint16_t totalLength = 20;
    std::uint16_t id = 0;
    std::uint16_t flagsFragment = 0;
    std::uint8_t ttl = 64;
    std::uint8_t protocol = 17;  // UDP
    std::uint16_t checksum = 0;
    IPv4 src = 0;
    IPv4 dst = 0;
};

enum class ParseError { None, TooShort, BadVersion, BadHeaderLength, BadTotalLength, BadChecksum };
const char* toString(ParseError e);

struct Packet {
    IPv4Header header;
    std::vector<std::uint8_t> payload;
};

// RFC 1071 Internet checksum. Over a valid header (checksum field included) it returns 0.
std::uint16_t internetChecksum(const std::uint8_t* data, std::size_t len);

// Zero-copy header validation + decode. This is what the forwarding path uses.
ParseError parseHeader(const std::uint8_t* data, std::size_t len, IPv4Header& out);

// Full parse (copies the payload).
ParseError parsePacket(const std::vector<std::uint8_t>& bytes, Packet& out);

// Serialize: fills in version/IHL/totalLength/checksum. Options are not generated.
std::vector<std::uint8_t> serialize(const Packet& p);

// Convenience builder for tests/demos.
std::vector<std::uint8_t> makePacket(IPv4 src, IPv4 dst, std::uint8_t ttl = 64,
                                     std::size_t payloadSize = 8, std::uint8_t protocol = 17);

// In-place TTL-- with RFC 1141 incremental checksum update. Returns false if TTL was already 0.
bool decrementTtl(std::uint8_t* data);

}  // namespace netsim

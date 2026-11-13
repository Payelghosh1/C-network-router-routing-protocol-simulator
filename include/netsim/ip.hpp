#pragma once
#include <cstdint>
#include <optional>
#include <string>

namespace netsim {

using IPv4 = std::uint32_t;  // host byte order

std::optional<IPv4> parseIPv4(const std::string& text);
std::string toString(IPv4 addr);
IPv4 mustParseIPv4(const std::string& text);  // throws std::invalid_argument

// CIDR prefix. `addr` is always stored masked (host bits cleared).
struct Prefix {
    IPv4 addr = 0;
    std::uint8_t len = 0;

    static Prefix make(IPv4 address, int length);
    static std::optional<Prefix> parse(const std::string& text);  // "10.0.0.0/8" or "1.2.3.4" (=/32)

    IPv4 mask() const { return len == 0 ? 0u : (~IPv4{0} << (32 - len)); }
    bool contains(IPv4 ip) const { return (ip & mask()) == addr; }
    std::string str() const;

    friend bool operator==(const Prefix& a, const Prefix& b) { return a.addr == b.addr && a.len == b.len; }
    friend bool operator<(const Prefix& a, const Prefix& b) {
        return a.addr != b.addr ? a.addr < b.addr : a.len < b.len;
    }
};

Prefix mustParsePrefix(const std::string& text);  // throws std::invalid_argument

}  // namespace netsim

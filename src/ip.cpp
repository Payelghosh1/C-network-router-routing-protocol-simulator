#include "netsim/ip.hpp"

#include <cctype>
#include <stdexcept>

namespace netsim {

std::optional<IPv4> parseIPv4(const std::string& s) {
    IPv4 value = 0;
    std::size_t i = 0;
    for (int octet = 0; octet < 4; ++octet) {
        if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) return std::nullopt;
        unsigned v = 0;
        int digits = 0;
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
            v = v * 10 + static_cast<unsigned>(s[i] - '0');
            ++i;
            if (++digits > 3 || v > 255) return std::nullopt;
        }
        value = (value << 8) | v;
        if (octet < 3) {
            if (i >= s.size() || s[i] != '.') return std::nullopt;
            ++i;
        }
    }
    if (i != s.size()) return std::nullopt;
    return value;
}

std::string toString(IPv4 a) {
    return std::to_string(a >> 24) + "." + std::to_string((a >> 16) & 0xff) + "." +
           std::to_string((a >> 8) & 0xff) + "." + std::to_string(a & 0xff);
}

IPv4 mustParseIPv4(const std::string& text) {
    auto v = parseIPv4(text);
    if (!v) throw std::invalid_argument("bad IPv4 address: " + text);
    return *v;
}

Prefix Prefix::make(IPv4 address, int length) {
    if (length < 0) length = 0;
    if (length > 32) length = 32;
    Prefix p;
    p.len = static_cast<std::uint8_t>(length);
    p.addr = address & p.mask();
    return p;
}

std::optional<Prefix> Prefix::parse(const std::string& text) {
    auto slash = text.find('/');
    if (slash == std::string::npos) {
        auto ip = parseIPv4(text);
        if (!ip) return std::nullopt;
        return make(*ip, 32);
    }
    auto ip = parseIPv4(text.substr(0, slash));
    if (!ip) return std::nullopt;
    std::string l = text.substr(slash + 1);
    if (l.empty() || l.size() > 2) return std::nullopt;
    int len = 0;
    for (char c : l) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
        len = len * 10 + (c - '0');
    }
    if (len > 32) return std::nullopt;
    return make(*ip, len);
}

std::string Prefix::str() const { return toString(addr) + "/" + std::to_string(len); }

Prefix mustParsePrefix(const std::string& text) {
    auto p = Prefix::parse(text);
    if (!p) throw std::invalid_argument("bad prefix: " + text);
    return *p;
}

}  // namespace netsim

#include "netsim/pcap.hpp"

namespace netsim {
namespace {
void le32(std::ofstream& o, std::uint32_t v) {
    char b[4] = {static_cast<char>(v & 0xff), static_cast<char>((v >> 8) & 0xff),
                 static_cast<char>((v >> 16) & 0xff), static_cast<char>((v >> 24) & 0xff)};
    o.write(b, 4);
}
void le16(std::ofstream& o, std::uint16_t v) {
    char b[2] = {static_cast<char>(v & 0xff), static_cast<char>((v >> 8) & 0xff)};
    o.write(b, 2);
}
}  // namespace

PcapWriter::PcapWriter(const std::string& path) : out_(path, std::ios::binary) {
    le32(out_, 0xa1b2c3d4);  // magic
    le16(out_, 2);           // version 2.4
    le16(out_, 4);
    le32(out_, 0);           // thiszone
    le32(out_, 0);           // sigfigs
    le32(out_, 65535);       // snaplen
    le32(out_, 101);         // LINKTYPE_RAW (bare IPv4/IPv6)
}

void PcapWriter::write(const std::uint8_t* data, std::size_t len) {
    const std::uint32_t us = tick_++ * 1000;
    le32(out_, 1700000000u + us / 1000000u);
    le32(out_, us % 1000000u);
    le32(out_, static_cast<std::uint32_t>(len));
    le32(out_, static_cast<std::uint32_t>(len));
    out_.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
}

}  // namespace netsim

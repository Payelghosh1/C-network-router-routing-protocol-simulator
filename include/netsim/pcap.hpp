#pragma once
#include <cstdint>
#include <fstream>
#include <string>

namespace netsim {

// Writes raw-IP packets (LINKTYPE_RAW = 101) to a classic .pcap file that Wireshark opens directly.
class PcapWriter {
public:
    explicit PcapWriter(const std::string& path);
    bool ok() const { return out_.good(); }
    void write(const std::uint8_t* data, std::size_t len);

private:
    std::ofstream out_;
    std::uint32_t tick_ = 0;  // fake timestamps: 1 ms apart
};

}  // namespace netsim

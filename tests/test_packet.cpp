#include <gtest/gtest.h>

#include <random>

#include "netsim/packet.hpp"

using namespace netsim;

TEST(Checksum, KnownVector) {
    // Classic example header from RFC 1071 discussions: checksum field 0xb861.
    std::uint8_t h[20] = {0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
                          0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};
    EXPECT_EQ(internetChecksum(h, 20), 0);
    h[10] = h[11] = 0;
    EXPECT_EQ(internetChecksum(h, 20), 0xb861);
}

TEST(Packet, SerializeParseRoundTrip) {
    Packet p;
    p.header.src = mustParseIPv4("1.2.3.4");
    p.header.dst = mustParseIPv4("5.6.7.8");
    p.header.ttl = 33;
    p.header.id = 0xbeef;
    p.payload = {1, 2, 3, 4, 5};
    auto bytes = serialize(p);
    ASSERT_EQ(bytes.size(), 25u);

    Packet q;
    ASSERT_EQ(parsePacket(bytes, q), ParseError::None);
    EXPECT_EQ(q.header.src, p.header.src);
    EXPECT_EQ(q.header.dst, p.header.dst);
    EXPECT_EQ(q.header.ttl, 33);
    EXPECT_EQ(q.header.id, 0xbeef);
    EXPECT_EQ(q.payload, p.payload);
}

TEST(Packet, DetectsMalformedInput) {
    Packet scratch;
    EXPECT_EQ(parsePacket({}, scratch), ParseError::TooShort);
    EXPECT_EQ(parsePacket(std::vector<std::uint8_t>(10), scratch), ParseError::TooShort);

    auto good = makePacket(1, 2);
    auto bad = good;
    bad[0] = 0x65;  // version 6
    EXPECT_EQ(parsePacket(bad, scratch), ParseError::BadVersion);
    bad = good;
    bad[0] = 0x43;  // IHL 3
    EXPECT_EQ(parsePacket(bad, scratch), ParseError::BadHeaderLength);
    bad = good;
    bad[3] = 0xff;  // total length bigger than buffer
    EXPECT_EQ(parsePacket(bad, scratch), ParseError::BadTotalLength);
    bad = good;
    bad[15] ^= 1;  // corrupt source, checksum now wrong
    EXPECT_EQ(parsePacket(bad, scratch), ParseError::BadChecksum);
}

TEST(Packet, IncrementalTtlUpdateKeepsChecksumValid) {
    std::mt19937 rng(7);
    for (int i = 0; i < 20000; ++i) {
        auto b = makePacket(static_cast<IPv4>(rng()), static_cast<IPv4>(rng()), static_cast<std::uint8_t>(1 + rng() % 255));
        const std::uint8_t before = b[8];
        ASSERT_TRUE(decrementTtl(b.data()));
        EXPECT_EQ(b[8], before - 1);
        IPv4Header h;
        ASSERT_EQ(parseHeader(b.data(), b.size(), h), ParseError::None) << "iteration " << i;
    }
}

TEST(Packet, DecrementTtlAtZeroFails) {
    auto b = makePacket(1, 2, 0);
    EXPECT_FALSE(decrementTtl(b.data()));
}

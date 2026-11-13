#include <gtest/gtest.h>

#include "netsim/ip.hpp"

using namespace netsim;

TEST(IPv4, ParsesValidAddresses) {
    EXPECT_EQ(*parseIPv4("0.0.0.0"), 0u);
    EXPECT_EQ(*parseIPv4("255.255.255.255"), 0xffffffffu);
    EXPECT_EQ(*parseIPv4("192.168.1.10"), 0xc0a8010au);
}

TEST(IPv4, RejectsInvalidAddresses) {
    for (const char* s : {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.", ".1.2.3", "a.b.c.d", "1..2.3",
                          "1.2.3.4 ", "0001.2.3.4", "-1.2.3.4"})
        EXPECT_FALSE(parseIPv4(s)) << s;
}

TEST(IPv4, RoundTrips) { EXPECT_EQ(toString(*parseIPv4("10.20.30.40")), "10.20.30.40"); }

TEST(Prefix, MasksHostBitsAndMatches) {
    Prefix p = mustParsePrefix("10.1.2.3/8");
    EXPECT_EQ(p.str(), "10.0.0.0/8");
    EXPECT_TRUE(p.contains(mustParseIPv4("10.255.0.1")));
    EXPECT_FALSE(p.contains(mustParseIPv4("11.0.0.1")));
}

TEST(Prefix, EdgeLengths) {
    EXPECT_TRUE(mustParsePrefix("0.0.0.0/0").contains(mustParseIPv4("8.8.8.8")));
    Prefix host = mustParsePrefix("1.2.3.4/32");
    EXPECT_TRUE(host.contains(mustParseIPv4("1.2.3.4")));
    EXPECT_FALSE(host.contains(mustParseIPv4("1.2.3.5")));
    EXPECT_EQ(mustParsePrefix("1.2.3.4").len, 32);
}

TEST(Prefix, RejectsInvalid) {
    for (const char* s : {"1.2.3.4/33", "1.2.3.4/", "1.2.3.4/x", "1.2.3/8", "/8"}) EXPECT_FALSE(Prefix::parse(s)) << s;
}

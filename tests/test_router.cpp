#include <gtest/gtest.h>

#include "netsim/router.hpp"

using namespace netsim;

static Router makeRouter(Router::FibType t = Router::FibType::Trie) {
    Router r("R", mustParseIPv4("9.9.9.9"), t);
    r.addConnected(mustParsePrefix("10.0.0.0/24"), "lan0");
    r.addStatic(mustParsePrefix("0.0.0.0/0"), mustParseIPv4("10.0.0.254"), "wan0");
    return r;
}

class RouterTest : public ::testing::TestWithParam<Router::FibType> {};

TEST_P(RouterTest, ForwardsAndDecrementsTtl) {
    Router r = makeRouter(GetParam());
    auto p = makePacket(mustParseIPv4("1.1.1.1"), mustParseIPv4("8.8.8.8"), 10);
    ForwardResult res = r.process(p);
    ASSERT_EQ(res.verdict, Verdict::Forwarded);
    EXPECT_EQ(res.route->iface, "wan0");
    EXPECT_EQ(p[8], 9);
    IPv4Header h;
    EXPECT_EQ(parseHeader(p.data(), p.size(), h), ParseError::None);  // checksum still valid
}

TEST_P(RouterTest, PrefersConnectedMoreSpecificRoute) {
    Router r = makeRouter(GetParam());
    auto p = makePacket(1, mustParseIPv4("10.0.0.7"));
    ForwardResult res = r.process(p);
    ASSERT_EQ(res.verdict, Verdict::Forwarded);
    EXPECT_EQ(res.route->iface, "lan0");
    EXPECT_EQ(res.route->nextHop, 0u);
}

TEST_P(RouterTest, DropsExpiredTtl) {
    Router r = makeRouter(GetParam());
    auto p = makePacket(1, mustParseIPv4("8.8.8.8"), 1);
    EXPECT_EQ(r.process(p).verdict, Verdict::DroppedTtl);
    auto z = makePacket(1, mustParseIPv4("8.8.8.8"), 0);
    EXPECT_EQ(r.process(z).verdict, Verdict::DroppedTtl);
}

TEST_P(RouterTest, DropsMalformed) {
    Router r = makeRouter(GetParam());
    std::vector<std::uint8_t> junk(5, 0xff);
    ForwardResult res = r.process(junk);
    EXPECT_EQ(res.verdict, Verdict::DroppedMalformed);
    EXPECT_EQ(res.error, ParseError::TooShort);
    auto p = makePacket(1, 2);
    p[16] ^= 0x40;
    EXPECT_EQ(r.process(p).error, ParseError::BadChecksum);
}

TEST_P(RouterTest, DropsWhenNoRoute) {
    Router r("R", mustParseIPv4("9.9.9.9"), GetParam());
    r.addConnected(mustParsePrefix("10.0.0.0/24"));
    auto p = makePacket(1, mustParseIPv4("8.8.8.8"));
    EXPECT_EQ(r.process(p).verdict, Verdict::DroppedNoRoute);
}

TEST_P(RouterTest, DeliversPacketsAddressedToItself) {
    Router r = makeRouter(GetParam());
    auto p = makePacket(1, mustParseIPv4("9.9.9.9"), 1);  // TTL 1 is fine for local delivery
    EXPECT_EQ(r.process(p).verdict, Verdict::DeliveredLocal);
}

TEST_P(RouterTest, CountsStats) {
    Router r = makeRouter(GetParam());
    auto ok = makePacket(1, mustParseIPv4("8.8.8.8"));
    auto ttl = makePacket(1, mustParseIPv4("8.8.8.8"), 1);
    std::vector<std::uint8_t> bad(3);
    r.process(ok);
    r.process(ttl);
    r.process(bad);
    EXPECT_EQ(r.stats().received, 3u);
    EXPECT_EQ(r.stats().forwarded, 1u);
    EXPECT_EQ(r.stats().droppedTtl, 1u);
    EXPECT_EQ(r.stats().droppedMalformed, 1u);
}

INSTANTIATE_TEST_SUITE_P(BothFibs, RouterTest, ::testing::Values(Router::FibType::Trie, Router::FibType::Linear));

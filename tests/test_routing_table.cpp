#include <gtest/gtest.h>

#include <random>
#include <set>

#include "netsim/routing_table.hpp"

using namespace netsim;

static Route R(const char* prefix, const char* nh, Source s = Source::Static, std::uint32_t metric = 0) {
    Route r;
    r.prefix = mustParsePrefix(prefix);
    r.nextHop = mustParseIPv4(nh);
    r.iface = "e0";
    r.source = s;
    r.metric = metric;
    return r;
}

template <typename T>
class TableTest : public ::testing::Test {};
using Tables = ::testing::Types<LinearTable, TrieTable>;
TYPED_TEST_SUITE(TableTest, Tables);

TYPED_TEST(TableTest, EmptyTableHasNoRoute) {
    TypeParam t;
    EXPECT_EQ(t.lookup(mustParseIPv4("1.2.3.4")), nullptr);
}

TYPED_TEST(TableTest, LongestPrefixWins) {
    TypeParam t;
    t.insert(R("0.0.0.0/0", "9.9.9.9"));
    t.insert(R("10.0.0.0/8", "1.1.1.1"));
    t.insert(R("10.1.0.0/16", "2.2.2.2"));
    t.insert(R("10.1.2.0/24", "3.3.3.3"));
    t.insert(R("10.1.2.3/32", "4.4.4.4"));

    EXPECT_EQ(t.lookup(mustParseIPv4("10.1.2.3"))->nextHop, mustParseIPv4("4.4.4.4"));
    EXPECT_EQ(t.lookup(mustParseIPv4("10.1.2.4"))->nextHop, mustParseIPv4("3.3.3.3"));
    EXPECT_EQ(t.lookup(mustParseIPv4("10.1.9.9"))->nextHop, mustParseIPv4("2.2.2.2"));
    EXPECT_EQ(t.lookup(mustParseIPv4("10.9.9.9"))->nextHop, mustParseIPv4("1.1.1.1"));
    EXPECT_EQ(t.lookup(mustParseIPv4("8.8.8.8"))->nextHop, mustParseIPv4("9.9.9.9"));
}

TYPED_TEST(TableTest, NoDefaultMeansNoRouteOutsidePrefixes) {
    TypeParam t;
    t.insert(R("192.168.0.0/16", "1.1.1.1"));
    EXPECT_EQ(t.lookup(mustParseIPv4("192.169.0.1")), nullptr);
    EXPECT_NE(t.lookup(mustParseIPv4("192.168.255.255")), nullptr);
}

TYPED_TEST(TableTest, InsertSamePrefixReplaces) {
    TypeParam t;
    t.insert(R("10.0.0.0/8", "1.1.1.1"));
    t.insert(R("10.0.0.0/8", "2.2.2.2"));
    EXPECT_EQ(t.lookup(mustParseIPv4("10.0.0.1"))->nextHop, mustParseIPv4("2.2.2.2"));
}

TYPED_TEST(TableTest, ClearEmptiesTable) {
    TypeParam t;
    t.insert(R("10.0.0.0/8", "1.1.1.1"));
    t.clear();
    EXPECT_EQ(t.size(), 0u);
    EXPECT_EQ(t.lookup(mustParseIPv4("10.0.0.1")), nullptr);
}

// Property test: the trie must agree with the trivially-correct linear scan on random data.
TEST(TrieVsLinear, AgreeOnRandomTables) {
    std::mt19937 rng(2024);
    for (int round = 0; round < 20; ++round) {
        LinearTable lin;
        TrieTable trie;
        std::set<Prefix> seen;
        const int n = 50 + round * 40;
        for (int i = 0; i < n; ++i) {
            // cluster addresses so prefixes actually overlap
            Prefix p = Prefix::make((rng() & 0xff000000u) | (rng() & 0x00ff0000u), static_cast<int>(rng() % 33));
            if (!seen.insert(p).second) continue;
            Route r = R("0.0.0.0/0", "0.0.0.1");
            r.prefix = p;
            r.nextHop = static_cast<IPv4>(rng());
            lin.insert(r);
            trie.insert(r);
        }
        for (int i = 0; i < 3000; ++i) {
            IPv4 d = (rng() & 0xff000000u) | (rng() & 0x00ff0000u) | (rng() & 0xffffu);
            const Route* a = lin.lookup(d);
            const Route* b = trie.lookup(d);
            ASSERT_EQ(a == nullptr, b == nullptr) << toString(d);
            if (a) {
                EXPECT_EQ(a->prefix, b->prefix) << toString(d);
                EXPECT_EQ(a->nextHop, b->nextHop);
            }
        }
    }
}

TEST(Rib, PrefersLowestAdminDistanceThenMetric) {
    Rib rib;
    rib.add(R("10.0.0.0/8", "1.1.1.1", Source::Ospf, 5));
    rib.add(R("10.0.0.0/8", "2.2.2.2", Source::Static, 50));
    rib.add(R("20.0.0.0/8", "3.3.3.3", Source::Ospf, 9));
    rib.add(R("20.0.0.0/8", "4.4.4.4", Source::Ospf, 3));
    auto best = rib.bestRoutes();
    ASSERT_EQ(best.size(), 2u);
    EXPECT_EQ(best[0].source, Source::Static);                    // AD 1 beats AD 110
    EXPECT_EQ(best[1].nextHop, mustParseIPv4("4.4.4.4"));         // same AD: lower metric
    EXPECT_EQ(rib.candidateCount(), 4u);
}

TEST(Rib, RemoveBySourceFallsBackToNextBest) {
    Rib rib;
    rib.add(R("10.0.0.0/8", "1.1.1.1", Source::Ospf, 5));
    rib.add(R("10.0.0.0/8", "2.2.2.2", Source::Static, 0));
    rib.removeBySource(Source::Static);
    auto best = rib.bestRoutes();
    ASSERT_EQ(best.size(), 1u);
    EXPECT_EQ(best[0].source, Source::Ospf);
    rib.removeBySource(Source::Ospf);
    EXPECT_TRUE(rib.bestRoutes().empty());
}

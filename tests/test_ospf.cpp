#include <gtest/gtest.h>

#include "netsim/network.hpp"

using namespace netsim;

namespace {
// R1 -1- R2 -1- R4 ; R1 -1- R3 -3- R4
Network diamond() {
    Network n;
    for (auto [name, id] : {std::pair{"R1", "1.1.1.1"}, {"R2", "2.2.2.2"}, {"R3", "3.3.3.3"}, {"R4", "4.4.4.4"}})
        n.addRouter(name, id);
    n.addNetwork("R1", "10.1.0.0/16");
    n.addNetwork("R2", "10.2.0.0/16");
    n.addNetwork("R3", "10.3.0.0/16");
    n.addNetwork("R4", "10.4.0.0/16");
    n.addLink("R1", "R2", 1);
    n.addLink("R2", "R4", 1);
    n.addLink("R1", "R3", 1);
    n.addLink("R3", "R4", 3);
    return n;
}
}  // namespace

TEST(Lsdb, KeepsOnlyNewerSequence) {
    Lsdb db;
    Lsa a;
    a.origin = "R1";
    a.seq = 5;
    EXPECT_TRUE(db.install(a));
    EXPECT_FALSE(db.install(a));  // duplicate
    a.seq = 4;
    EXPECT_FALSE(db.install(a));  // stale
    a.seq = 6;
    EXPECT_TRUE(db.install(a));
    EXPECT_EQ(db.find("R1")->seq, 6u);
}

TEST(Ospf, EveryRouterLearnsFullDatabase) {
    Network n = diamond();
    n.runOspf();
    for (const char* r : {"R1", "R2", "R3", "R4"}) EXPECT_EQ(n.router(r).lsdb().size(), 4u) << r;
}

TEST(Ospf, ComputesShortestPathCosts) {
    Network n = diamond();
    n.runOspf();
    auto spf = computeSpf(n.router("R1").lsdb(), "R1");
    EXPECT_EQ(spf["R1"].cost, 0u);
    EXPECT_EQ(spf["R2"].cost, 1u);
    EXPECT_EQ(spf["R3"].cost, 1u);
    EXPECT_EQ(spf["R4"].cost, 2u);          // via R2, not via R3 (1+3)
    EXPECT_EQ(spf["R4"].firstHop, "R2");
}

TEST(Ospf, InstallsRoutesAndForwardsAlongShortestPath) {
    Network n = diamond();
    n.runOspf();
    auto pkt = makePacket(mustParseIPv4("10.1.0.5"), mustParseIPv4("10.4.1.5"));
    TraceResult t = n.trace("R1", pkt);
    EXPECT_TRUE(t.delivered) << t.outcome;
    ASSERT_EQ(t.hops.size(), 3u);
    EXPECT_EQ(t.hops[0].router, "R1");
    EXPECT_EQ(t.hops[1].router, "R2");
    EXPECT_EQ(t.hops[2].router, "R4");
}

TEST(Ospf, ReroutesAfterLinkFailureAndBack) {
    Network n = diamond();
    n.runOspf();
    n.setLinkState("R2", "R4", false);
    n.runOspf();
    auto pkt = makePacket(mustParseIPv4("10.1.0.5"), mustParseIPv4("10.4.1.5"));
    TraceResult t = n.trace("R1", pkt);
    EXPECT_TRUE(t.delivered) << t.outcome;
    ASSERT_EQ(t.hops.size(), 3u);
    EXPECT_EQ(t.hops[1].router, "R3");  // detour
    EXPECT_EQ(computeSpf(n.router("R1").lsdb(), "R1")["R4"].cost, 4u);

    n.setLinkState("R2", "R4", true);
    n.runOspf();
    EXPECT_EQ(n.trace("R1", pkt).hops[1].router, "R2");  // back on the short path
}

TEST(Ospf, TrafficDropsWhileRoutingIsStale) {
    Network n = diamond();
    n.runOspf();
    n.setLinkState("R2", "R4", false);  // no reconvergence yet
    auto pkt = makePacket(mustParseIPv4("10.1.0.5"), mustParseIPv4("10.4.1.5"));
    TraceResult t = n.trace("R1", pkt);
    EXPECT_FALSE(t.delivered);
    EXPECT_NE(t.outcome.find("down"), std::string::npos);
}

TEST(Ospf, PartitionedNetworkLosesRoutes) {
    Network n = diamond();
    n.runOspf();
    n.setLinkState("R1", "R2", false);
    n.setLinkState("R1", "R3", false);
    n.runOspf();
    auto spf = computeSpf(n.router("R1").lsdb(), "R1");
    EXPECT_EQ(spf.size(), 1u);  // only itself; stale LSAs are ignored by the two-way check
    auto pkt = makePacket(mustParseIPv4("10.1.0.5"), mustParseIPv4("10.4.1.5"));
    EXPECT_EQ(n.trace("R1", pkt).outcome, "dropped (no route)");
}

TEST(Ospf, OneWayLinkIsNotUsed) {
    Lsdb db;
    Lsa a{"A", 1, 1, {{"B", 1}}, {}};
    Lsa b{"B", 2, 1, {}, {}};  // B does not list A
    db.install(a);
    db.install(b);
    auto spf = computeSpf(db, "A");
    EXPECT_EQ(spf.count("B"), 0u);
}

TEST(Ospf, StaticRouteBeatsOspfByAdminDistance) {
    Network n = diamond();
    n.runOspf();
    // static route for R4's network pointing at R3 (AD 1 < OSPF's 110)
    n.router("R1").addStatic(mustParsePrefix("10.4.0.0/16"), mustParseIPv4("3.3.3.3"), "to-R3");
    auto t = n.trace("R1", makePacket(mustParseIPv4("10.1.0.5"), mustParseIPv4("10.4.1.5")));
    EXPECT_EQ(t.hops[1].router, "R3");
    // OSPF reconvergence must not clobber the static route
    n.runOspf();
    t = n.trace("R1", makePacket(mustParseIPv4("10.1.0.5"), mustParseIPv4("10.4.1.5")));
    EXPECT_EQ(t.hops[1].router, "R3");
}

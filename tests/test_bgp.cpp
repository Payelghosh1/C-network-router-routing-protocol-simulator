#include <gtest/gtest.h>

#include "netsim/bgp.hpp"

using namespace netsim;

static BgpRoute base() {
    BgpRoute r;
    r.prefix = mustParsePrefix("203.0.113.0/24");
    r.asPath = {65010, 65030};
    r.peerRouterId = 10;
    return r;
}

TEST(BgpDecision, HighestLocalPrefWinsFirst) {
    BgpRoute a = base(), b = base();
    a.localPref = 200;
    a.asPath = {1, 2, 3, 4};  // much longer path, but policy wins
    auto d = compareRoutes(a, b, {});
    EXPECT_TRUE(d.firstWins);
    EXPECT_EQ(d.reason, "highest LOCAL_PREF");
}

TEST(BgpDecision, ShortestAsPath) {
    BgpRoute a = base(), b = base();
    b.asPath = {65011};
    auto d = compareRoutes(a, b, {});
    EXPECT_FALSE(d.firstWins);
    EXPECT_EQ(d.reason, "shortest AS_PATH");
}

TEST(BgpDecision, LowestOrigin) {
    BgpRoute a = base(), b = base();
    a.origin = Origin::Incomplete;
    EXPECT_FALSE(compareRoutes(a, b, {}).firstWins);
    EXPECT_EQ(compareRoutes(a, b, {}).reason, "lowest ORIGIN");
}

TEST(BgpDecision, MedOnlyComparedWithinSameNeighborAs) {
    BgpRoute a = base(), b = base();
    a.med = 100;
    b.med = 5;
    b.peerRouterId = 99;
    // same neighbour AS (65010): MED decides -> b wins
    EXPECT_FALSE(compareRoutes(a, b, {}).firstWins);
    EXPECT_EQ(compareRoutes(a, b, {}).reason, "lowest MED");
    // different neighbour AS: MED ignored, falls through to router-id -> a (id 10) wins
    b.asPath = {65099, 65030};
    auto d = compareRoutes(a, b, {});
    EXPECT_TRUE(d.firstWins);
    EXPECT_EQ(d.reason, "lowest router-id");
    // ...unless the operator enables always-compare-med
    BgpPolicy p;
    p.alwaysCompareMed = true;
    EXPECT_FALSE(compareRoutes(a, b, p).firstWins);
}

TEST(BgpDecision, EbgpOverIbgpThenIgpMetricThenRouterId) {
    BgpRoute a = base(), b = base();
    a.ebgp = false;
    EXPECT_EQ(compareRoutes(a, b, {}).reason, "eBGP over iBGP");
    EXPECT_FALSE(compareRoutes(a, b, {}).firstWins);

    a = base();
    b = base();
    a.igpMetric = 30;
    b.igpMetric = 10;
    EXPECT_EQ(compareRoutes(a, b, {}).reason, "lowest IGP metric to next hop");
    EXPECT_FALSE(compareRoutes(a, b, {}).firstWins);

    a = base();
    b = base();
    b.peerRouterId = 3;
    EXPECT_EQ(compareRoutes(a, b, {}).reason, "lowest router-id");
    EXPECT_FALSE(compareRoutes(a, b, {}).firstWins);
}

TEST(BgpDecision, PolicyCanDisableSteps) {
    BgpRoute a = base(), b = base();
    a.localPref = 200;
    BgpPolicy p;
    p.useLocalPref = false;
    b.asPath = {1};  // shorter
    auto d = compareRoutes(a, b, p);
    EXPECT_FALSE(d.firstWins);
    EXPECT_EQ(d.reason, "shortest AS_PATH");
}

TEST(BgpSpeaker, LoopPreventionRejectsOwnAsn) {
    BgpSpeaker s(65001, 1);
    BgpRoute r = base();
    r.asPath = {65010, 65001, 65030};
    EXPECT_FALSE(s.receive(r));
    EXPECT_EQ(s.rejected(), 1u);
    EXPECT_TRUE(s.selectBest().empty());
}

TEST(BgpSpeaker, SelectsBestAcrossManyCandidatesRegardlessOfArrivalOrder) {
    BgpRoute a = base(), b = base(), c = base();
    a.nextHop = 1;
    a.asPath = {1, 2, 3};
    b.nextHop = 2;
    b.asPath = {4, 3};
    c.nextHop = 3;
    c.asPath = {4, 3};  // same neighbour AS as b, so MED is compared: b (MED 0) beats c (MED 9)
    c.med = 9;
    BgpRoute* order[3][3] = {{&a, &b, &c}, {&c, &b, &a}, {&b, &a, &c}};
    for (auto& o : order) {
        BgpSpeaker s(65001, 1);
        for (BgpRoute* r : o) s.receive(*r);
        auto best = s.selectBest();
        ASSERT_EQ(best.size(), 1u);
        EXPECT_EQ(best.begin()->second.best.nextHop, 2u);  // 2-hop path, lowest MED among equals
        EXPECT_EQ(best.begin()->second.candidates, 3u);
    }
}

TEST(BgpSpeaker, ExportPrependsAsnAndResetsLocalPref) {
    BgpSpeaker s(65001, 1);
    BgpRoute r = base();
    r.localPref = 300;
    BgpRoute out = s.exportTo(r, mustParseIPv4("1.1.1.1"));
    EXPECT_EQ(out.asPath.front(), 65001u);
    EXPECT_EQ(out.asPath.size(), 3u);
    EXPECT_EQ(out.localPref, 100u);
    EXPECT_EQ(out.nextHop, mustParseIPv4("1.1.1.1"));
}

TEST(BgpSpeaker, ToRoutesUsesBgpAdminDistances) {
    BgpSpeaker s(65001, 1);
    BgpRoute r = base();
    s.receive(r);
    auto routes = s.toRoutes();
    ASSERT_EQ(routes.size(), 1u);
    EXPECT_EQ(routes[0].source, Source::BgpExternal);
    EXPECT_EQ(adminDistance(routes[0].source), 20);
}

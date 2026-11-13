// End-to-end walkthrough: OSPF convergence, packet tracing, link failure + reconvergence, BGP path selection.
#include <algorithm>
#include <cstdio>

#include "netsim/bgp.hpp"
#include "netsim/network.hpp"

using namespace netsim;

static void printFib(const Router& r) {
    auto routes = r.fib().routes();
    std::sort(routes.begin(), routes.end(), [](const Route& a, const Route& b) { return a.prefix < b.prefix; });
    std::printf("  FIB of %s (%s, %zu routes)\n", r.name().c_str(), r.fib().name(), routes.size());
    for (const Route& x : routes) {
        std::printf("    %-18s %-10s metric %-3u via %-12s %s\n", x.prefix.str().c_str(), toString(x.source),
                    x.metric, x.nextHop ? toString(x.nextHop).c_str() : "-", x.iface.c_str());
    }
}

static void printTrace(const TraceResult& t) {
    for (const TraceHop& h : t.hops)
        std::printf("    %-3s %-22s %s\n", h.router.c_str(), toString(h.verdict), h.detail.c_str());
    std::printf("    => %s\n", t.outcome.c_str());
}

int main() {
    std::printf("=== 1. OSPF on a 4-router topology ===\n");
    //      R1 --1-- R2
    //      |         |
    //      1         1
    //      |         |
    //      R3 --3-- R4
    Network net;
    net.addRouter("R1", "1.1.1.1");
    net.addRouter("R2", "2.2.2.2");
    net.addRouter("R3", "3.3.3.3");
    net.addRouter("R4", "4.4.4.4");
    net.addNetwork("R1", "10.1.0.0/16");
    net.addNetwork("R2", "10.2.0.0/16");
    net.addNetwork("R3", "10.3.0.0/16");
    net.addNetwork("R4", "10.4.0.0/16");
    net.addLink("R1", "R2", 1);
    net.addLink("R2", "R4", 1);
    net.addLink("R1", "R3", 1);
    net.addLink("R3", "R4", 3);

    OspfRunStats s = net.runOspf();
    std::printf("  converged: %zu LSA deliveries, %zu SPF runs\n", s.lsaMessages, s.spfRuns);
    printFib(net.router("R1"));

    std::printf("\n=== 2. Trace 10.1.0.5 -> 10.4.1.5 (captured to demo.pcap) ===\n");
    PcapWriter pcap("demo.pcap");
    auto pkt = makePacket(mustParseIPv4("10.1.0.5"), mustParseIPv4("10.4.1.5"), 64, 16, 17);
    printTrace(net.trace("R1", pkt, &pcap));

    std::printf("\n=== 3. Link R2-R4 fails -> OSPF reconverges ===\n");
    net.setLinkState("R2", "R4", false);
    auto stale = net.trace("R1", pkt);  // before reconvergence: R2 still points at the dead link
    std::printf("  before reconvergence:\n");
    printTrace(stale);
    s = net.runOspf();
    std::printf("  after reconvergence (%zu LSA deliveries):\n", s.lsaMessages);
    printFib(net.router("R1"));
    printTrace(net.trace("R1", pkt, &pcap));

    std::printf("\n=== 4. Error handling ===\n");
    auto expiring = makePacket(mustParseIPv4("10.1.0.5"), mustParseIPv4("10.4.1.5"), 2);
    std::printf("  TTL=2 (needs 3 hops):\n");
    printTrace(net.trace("R1", expiring));
    auto corrupt = pkt;
    corrupt[12] ^= 0xff;  // flip bits in src address without fixing the checksum
    std::printf("  corrupted header:\n");
    printTrace(net.trace("R1", corrupt));
    auto nowhere = makePacket(mustParseIPv4("10.1.0.5"), mustParseIPv4("172.16.0.1"));
    std::printf("  no route:\n");
    printTrace(net.trace("R1", nowhere));

    std::printf("\n=== 5. BGP best-path selection for 203.0.113.0/24 ===\n");
    BgpSpeaker bgp(65001, mustParseIPv4("1.1.1.1"));
    Prefix pfx = mustParsePrefix("203.0.113.0/24");
    auto mk = [&](const char* nh, uint32_t lp, std::vector<uint32_t> path, uint32_t med, bool ebgp, uint32_t rid) {
        BgpRoute r;
        r.prefix = pfx;
        r.nextHop = mustParseIPv4(nh);
        r.localPref = lp;
        r.asPath = std::move(path);
        r.med = med;
        r.ebgp = ebgp;
        r.peerRouterId = rid;
        return r;
    };
    bgp.receive(mk("192.0.2.1", 100, {65010, 65020, 65030}, 0, true, 10));
    bgp.receive(mk("192.0.2.2", 100, {65011, 65030}, 50, true, 11));
    bgp.receive(mk("192.0.2.3", 100, {65012, 65030}, 10, true, 12));
    bgp.receive(mk("192.0.2.4", 100, {65013, 65001, 65030}, 0, true, 13));  // contains our ASN -> loop
    std::printf("  rejected by loop prevention: %zu\n", bgp.rejected());
    for (const auto& [p, sel] : bgp.selectBest())
        std::printf("  %s: best next hop %s, AS_PATH len %zu, of %zu candidates; decided by: %s\n",
                    p.str().c_str(), toString(sel.best.nextHop).c_str(), sel.best.asPath.size(), sel.candidates,
                    sel.reason.c_str());
    // Same inputs, but the operator raises LOCAL_PREF on the long path: policy beats path length.
    BgpSpeaker pref(65001, mustParseIPv4("1.1.1.1"));
    pref.receive(mk("192.0.2.1", 200, {65010, 65020, 65030}, 0, true, 10));
    pref.receive(mk("192.0.2.2", 100, {65011, 65030}, 50, true, 11));
    for (const auto& [p, sel] : pref.selectBest())
        std::printf("  with LOCAL_PREF 200 on the long path: next hop %s, decided by: %s\n",
                    toString(sel.best.nextHop).c_str(), sel.reason.c_str());

    // Feed BGP routes into a router's RIB; they compete with OSPF/static by administrative distance.
    Router& r1 = net.router("R1");
    r1.replaceRoutes({Source::BgpExternal, Source::BgpInternal}, bgp.toRoutes());
    const Route* hit = r1.fib().lookup(mustParseIPv4("203.0.113.77"));
    std::printf("  R1 FIB lookup 203.0.113.77 -> %s via %s (%s)\n", hit->prefix.str().c_str(),
                toString(hit->nextHop).c_str(), toString(hit->source));
    return 0;
}

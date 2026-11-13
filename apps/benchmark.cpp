// Linear scan vs trie: lookup latency as the routing table grows, plus end-to-end forwarding throughput.
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <set>

#include "netsim/router.hpp"

using namespace netsim;
using Clock = std::chrono::steady_clock;

static double nsPerOp(Clock::time_point t0, Clock::time_point t1, std::size_t ops) {
    return std::chrono::duration<double, std::nano>(t1 - t0).count() / static_cast<double>(ops);
}

static std::vector<Route> makeRoutes(std::size_t n, std::mt19937& rng) {
    std::set<Prefix> seen;
    std::vector<Route> routes;
    std::uniform_int_distribution<std::uint32_t> any;
    std::uniform_int_distribution<int> pct(0, 99);
    while (routes.size() < n) {
        int len;
        int p = pct(rng);  // rough shape of a real BGP table: dominated by /24s
        if (p < 10) len = 8 + static_cast<int>(rng() % 9);        // /8 - /16
        else if (p < 35) len = 17 + static_cast<int>(rng() % 7);  // /17 - /23
        else if (p < 85) len = 24;
        else len = 25 + static_cast<int>(rng() % 8);              // /25 - /32
        Prefix pf = Prefix::make(any(rng), len);
        if (!seen.insert(pf).second) continue;
        Route r;
        r.prefix = pf;
        r.nextHop = any(rng) | 1;
        r.iface = "eth" + std::to_string(rng() % 8);
        r.metric = static_cast<std::uint32_t>(rng() % 100);
        r.source = Source::Static;
        routes.push_back(r);
    }
    return routes;
}

int main(int argc, char** argv) {
    const std::size_t maxSize = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 100000;
    std::mt19937 rng(12345);
    volatile std::uint64_t sink = 0;

    std::printf("Route lookup latency (random destinations)\n");
    std::printf("%10s | %12s | %12s | %8s | %10s\n", "routes", "linear ns/op", "trie ns/op", "speedup", "trie nodes");
    std::printf("-----------+--------------+--------------+----------+-----------\n");
    for (std::size_t n : {std::size_t{1000}, std::size_t{10000}, std::size_t{100000}}) {
        if (n > maxSize) break;
        auto routes = makeRoutes(n, rng);
        LinearTable lin;
        TrieTable trie;
        for (const Route& r : routes) {
            lin.insert(r);
            trie.insert(r);
        }

        const std::size_t trieOps = 1000000, linOps = 2000;
        std::vector<IPv4> dsts(trieOps);
        for (auto& d : dsts) d = static_cast<IPv4>(rng());

        // correctness cross-check before timing anything
        for (std::size_t i = 0; i < linOps; ++i) {
            const Route* a = lin.lookup(dsts[i]);
            const Route* b = trie.lookup(dsts[i]);
            if ((a == nullptr) != (b == nullptr) || (a && !(a->prefix == b->prefix))) {
                std::printf("MISMATCH for %s\n", toString(dsts[i]).c_str());
                return 1;
            }
        }

        auto t0 = Clock::now();
        for (std::size_t i = 0; i < linOps; ++i) {
            const Route* r = lin.lookup(dsts[i]);
            sink += r ? r->nextHop : 0;
        }
        auto t1 = Clock::now();
        for (std::size_t i = 0; i < trieOps; ++i) {
            const Route* r = trie.lookup(dsts[i]);
            sink += r ? r->nextHop : 0;
        }
        auto t2 = Clock::now();
        const double l = nsPerOp(t0, t1, linOps), t = nsPerOp(t1, t2, trieOps);
        std::printf("%10zu | %12.1f | %12.1f | %7.0fx | %10zu\n", n, l, t, l / t, trie.nodeCount());
    }

    std::printf("\nEnd-to-end forwarding (header validation + LPM + TTL/checksum update), 100k-route FIB\n");
    std::printf("%10s | %12s | %10s\n", "FIB", "ns/packet", "Mpps");
    std::printf("-----------+--------------+-----------\n");
    const std::size_t fibSize = std::min<std::size_t>(maxSize, 100000);
    auto routes = makeRoutes(fibSize, rng);
    Route def;
    def.prefix = Prefix::make(0, 0);
    def.nextHop = 1;
    def.iface = "default";
    routes.push_back(def);
    for (auto type : {Router::FibType::Trie, Router::FibType::Linear}) {
        Router r("bench", mustParseIPv4("9.9.9.9"), type);
        r.replaceRoutes({Source::Static}, routes);
        const std::size_t count = type == Router::FibType::Trie ? 500000 : 2000;
        std::vector<std::vector<std::uint8_t>> pkts;
        pkts.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
            pkts.push_back(makePacket(static_cast<IPv4>(rng()), static_cast<IPv4>(rng()), 64, 32));
        auto t0 = Clock::now();
        for (auto& p : pkts) sink += static_cast<std::uint64_t>(r.process(p).verdict);
        auto t1 = Clock::now();
        const double ns = nsPerOp(t0, t1, count);
        std::printf("%10s | %12.1f | %10.2f\n", r.fib().name(), ns, 1000.0 / ns);
    }
    (void)sink;
    return 0;
}

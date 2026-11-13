#include "netsim/router.hpp"

namespace netsim {

const char* toString(Verdict v) {
    switch (v) {
        case Verdict::Forwarded: return "forwarded";
        case Verdict::DeliveredLocal: return "delivered to router";
        case Verdict::DroppedMalformed: return "dropped (malformed)";
        case Verdict::DroppedTtl: return "dropped (TTL expired)";
        case Verdict::DroppedNoRoute: return "dropped (no route)";
    }
    return "?";
}

Router::Router(std::string name, IPv4 id, FibType type) : name_(std::move(name)), id_(id) {
    if (type == FibType::Trie) fib_ = std::make_unique<TrieTable>();
    else fib_ = std::make_unique<LinearTable>();
}

void Router::addConnected(const Prefix& p, const std::string& iface) {
    connected_.push_back(p);
    Route r;
    r.prefix = p;
    r.iface = iface;
    r.source = Source::Connected;
    rib_.add(r);
    rebuildFib();
}

void Router::addStatic(const Prefix& p, IPv4 nextHop, const std::string& iface, std::uint32_t metric) {
    Route r;
    r.prefix = p;
    r.nextHop = nextHop;
    r.iface = iface;
    r.metric = metric;
    r.source = Source::Static;
    rib_.add(r);
    rebuildFib();
}

void Router::replaceRoutes(const std::vector<Source>& sources, const std::vector<Route>& routes) {
    for (Source s : sources) rib_.removeBySource(s);
    for (const Route& r : routes) rib_.add(r);
    rebuildFib();
}

void Router::rebuildFib() {
    fib_->clear();
    for (const Route& r : rib_.bestRoutes()) fib_->insert(r);
}

ForwardResult Router::process(std::uint8_t* data, std::size_t len) {
    ++stats_.received;
    ForwardResult res;

    IPv4Header h;
    res.error = parseHeader(data, len, h);
    if (res.error != ParseError::None) {
        ++stats_.droppedMalformed;
        res.verdict = Verdict::DroppedMalformed;
        return res;
    }
    if (h.dst == id_) {
        ++stats_.delivered;
        res.verdict = Verdict::DeliveredLocal;
        return res;
    }
    if (h.ttl <= 1) {  // a real router would emit ICMP Time Exceeded here
        ++stats_.droppedTtl;
        res.verdict = Verdict::DroppedTtl;
        return res;
    }
    res.route = fib_->lookup(h.dst);
    if (!res.route) {  // a real router would emit ICMP Destination Unreachable here
        ++stats_.droppedNoRoute;
        res.verdict = Verdict::DroppedNoRoute;
        return res;
    }
    decrementTtl(data);
    ++stats_.forwarded;
    res.verdict = Verdict::Forwarded;
    return res;
}

}  // namespace netsim

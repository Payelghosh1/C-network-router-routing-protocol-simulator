#include "netsim/network.hpp"

#include <queue>
#include <stdexcept>

namespace netsim {

Router& Network::addRouter(const std::string& name, const std::string& routerId, Router::FibType fib) {
    const IPv4 id = mustParseIPv4(routerId);
    if (routers_.count(name)) throw std::invalid_argument("duplicate router: " + name);
    auto [it, ok] = routers_.emplace(name, Router(name, id, fib));
    (void)ok;
    idToName_[id] = name;
    return it->second;
}

void Network::addNetwork(const std::string& router, const std::string& prefix) {
    routers_.at(router).addConnected(mustParsePrefix(prefix), "lan0");
}

void Network::addLink(const std::string& a, const std::string& b, std::uint32_t cost) {
    if (!routers_.count(a) || !routers_.count(b)) throw std::invalid_argument("unknown router in link");
    links_.push_back(Link{a, b, cost, true});
}

bool Network::setLinkState(const std::string& a, const std::string& b, bool up) {
    for (Link& l : links_) {
        if ((l.a == a && l.b == b) || (l.a == b && l.b == a)) {
            l.up = up;
            return true;
        }
    }
    return false;
}

const Link* Network::findLink(const std::string& a, const std::string& b) const {
    for (const Link& l : links_)
        if ((l.a == a && l.b == b) || (l.a == b && l.b == a)) return &l;
    return nullptr;
}

std::vector<std::string> Network::upNeighbors(const std::string& name) const {
    std::vector<std::string> out;
    for (const Link& l : links_) {
        if (!l.up) continue;
        if (l.a == name) out.push_back(l.b);
        else if (l.b == name) out.push_back(l.a);
    }
    return out;
}

OspfRunStats Network::runOspf() {
    OspfRunStats stats;

    struct Msg {
        std::string to;
        Lsa lsa;
        std::string from;
    };
    std::queue<Msg> flood;

    // 1. Every router originates a fresh LSA describing its live links and attached networks.
    for (auto& [name, r] : routers_) {
        Lsa lsa;
        lsa.origin = name;
        lsa.address = r.id();
        lsa.seq = ++lsaSeq_[name];
        for (const Link& l : links_) {
            if (!l.up) continue;
            if (l.a == name) lsa.links.push_back({l.b, l.cost});
            else if (l.b == name) lsa.links.push_back({l.a, l.cost});
        }
        lsa.networks = r.connected();
        r.lsdb().install(lsa);
        for (const std::string& n : upNeighbors(name)) flood.push({n, lsa, name});
    }

    // 2. Flood: install if newer, and re-flood to every neighbour except the one it came from.
    while (!flood.empty()) {
        Msg m = std::move(flood.front());
        flood.pop();
        ++stats.lsaMessages;
        if (routers_.at(m.to).lsdb().install(m.lsa)) {
            for (const std::string& n : upNeighbors(m.to))
                if (n != m.from) flood.push({n, m.lsa, m.to});
        }
    }

    // 3. Each router runs SPF on its own LSDB and installs the resulting routes.
    for (auto& [name, r] : routers_) {
        auto spf = computeSpf(r.lsdb(), name);
        r.replaceRoutes({Source::Ospf}, routesFromSpf(r.lsdb(), name, spf));
        ++stats.spfRuns;
    }
    return stats;
}

TraceResult Network::trace(const std::string& src, std::vector<std::uint8_t> packet, PcapWriter* pcap,
                           int maxHops) {
    TraceResult tr;
    std::string cur = src;
    for (int hop = 0; hop < maxHops; ++hop) {
        Router& r = routers_.at(cur);
        if (pcap) pcap->write(packet.data(), packet.size());
        ForwardResult res = r.process(packet);

        TraceHop th{cur, res.verdict, ""};
        if (res.verdict != Verdict::Forwarded) {
            tr.delivered = (res.verdict == Verdict::DeliveredLocal);
            tr.outcome = toString(res.verdict);
            tr.hops.push_back(th);
            return tr;
        }
        const Route& route = *res.route;
        th.detail = route.prefix.str() + " [" + toString(route.source) + ", metric " +
                    std::to_string(route.metric) + "] via " +
                    (route.nextHop ? toString(route.nextHop) : std::string("connected")) + " (" + route.iface + ")";
        tr.hops.push_back(th);

        if (route.nextHop == 0) {  // destination is on a directly attached network
            tr.delivered = true;
            tr.outcome = "delivered to attached network " + route.prefix.str() + " on " + cur;
            return tr;
        }
        auto it = idToName_.find(route.nextHop);
        if (it == idToName_.end()) {
            tr.outcome = "next hop " + toString(route.nextHop) + " is not a known router";
            return tr;
        }
        const Link* link = findLink(cur, it->second);
        if (!link || !link->up) {
            tr.outcome = "dropped: link " + cur + "-" + it->second + " is down";
            return tr;
        }
        cur = it->second;
    }
    tr.outcome = "dropped: hop limit exceeded (routing loop?)";
    return tr;
}

}  // namespace netsim

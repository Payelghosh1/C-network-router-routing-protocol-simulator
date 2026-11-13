#include "netsim/ospf.hpp"

#include <algorithm>
#include <functional>
#include <queue>
#include <tuple>

namespace netsim {

bool Lsdb::install(const Lsa& lsa) {
    auto it = db_.find(lsa.origin);
    if (it != db_.end() && it->second.seq >= lsa.seq) return false;
    db_[lsa.origin] = lsa;
    return true;
}

const Lsa* Lsdb::find(const std::string& origin) const {
    auto it = db_.find(origin);
    return it == db_.end() ? nullptr : &it->second;
}

std::map<std::string, SpfEntry> computeSpf(const Lsdb& db, const std::string& self) {
    std::map<std::string, SpfEntry> done;
    using QE = std::tuple<std::uint32_t, std::string, std::string>;  // cost, node, firstHop
    std::priority_queue<QE, std::vector<QE>, std::greater<QE>> pq;
    pq.emplace(0, self, "");

    while (!pq.empty()) {
        auto [cost, node, first] = pq.top();
        pq.pop();
        if (done.count(node)) continue;
        done[node] = SpfEntry{cost, first};

        const Lsa* lsa = db.find(node);
        if (!lsa) continue;
        for (const LsaLink& l : lsa->links) {
            if (done.count(l.neighbor)) continue;
            const Lsa* peer = db.find(l.neighbor);
            if (!peer) continue;
            const bool twoWay = std::any_of(peer->links.begin(), peer->links.end(),
                                            [&](const LsaLink& back) { return back.neighbor == node; });
            if (!twoWay) continue;
            pq.emplace(cost + l.cost, l.neighbor, node == self ? l.neighbor : first);
        }
    }
    return done;
}

std::vector<Route> routesFromSpf(const Lsdb& db, const std::string& self,
                                 const std::map<std::string, SpfEntry>& spf) {
    std::vector<Route> routes;
    for (const auto& [dest, entry] : spf) {
        if (dest == self) continue;
        const Lsa* destLsa = db.find(dest);
        const Lsa* hopLsa = db.find(entry.firstHop);
        if (!destLsa || !hopLsa) continue;
        for (const Prefix& net : destLsa->networks) {
            Route r;
            r.prefix = net;
            r.nextHop = hopLsa->address;
            r.iface = "to-" + entry.firstHop;
            r.metric = entry.cost;
            r.source = Source::Ospf;
            routes.push_back(r);
        }
    }
    return routes;
}

}  // namespace netsim

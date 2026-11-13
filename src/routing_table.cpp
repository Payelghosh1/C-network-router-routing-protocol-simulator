#include "netsim/routing_table.hpp"

#include <algorithm>

namespace netsim {

const char* toString(Source s) {
    switch (s) {
        case Source::Connected: return "connected";
        case Source::Static: return "static";
        case Source::BgpExternal: return "bgp-ext";
        case Source::Ospf: return "ospf";
        case Source::BgpInternal: return "bgp-int";
    }
    return "?";
}

int adminDistance(Source s) {
    switch (s) {
        case Source::Connected: return 0;
        case Source::Static: return 1;
        case Source::BgpExternal: return 20;
        case Source::Ospf: return 110;
        case Source::BgpInternal: return 200;
    }
    return 255;
}

// ---- LinearTable ----------------------------------------------------------
const Route* LinearTable::lookup(IPv4 dst) const {
    const Route* best = nullptr;
    for (const Route& r : routes_) {
        if (r.prefix.contains(dst) && (best == nullptr || r.prefix.len >= best->prefix.len)) best = &r;
    }
    return best;
}

// ---- TrieTable ------------------------------------------------------------
void TrieTable::clear() {
    nodes_.clear();
    routes_.clear();
    nodes_.emplace_back();  // root
}

void TrieTable::insert(const Route& r) {
    std::int32_t node = 0;
    for (int i = 0; i < r.prefix.len; ++i) {
        const int bit = (r.prefix.addr >> (31 - i)) & 1;
        if (nodes_[node].child[bit] < 0) {
            const auto idx = static_cast<std::int32_t>(nodes_.size());
            nodes_.emplace_back();  // may reallocate: never hold a Node& across this
            nodes_[node].child[bit] = idx;
        }
        node = nodes_[node].child[bit];
    }
    if (nodes_[node].route < 0) {
        nodes_[node].route = static_cast<std::int32_t>(routes_.size());
        routes_.push_back(r);
    } else {
        routes_[nodes_[node].route] = r;
    }
}

const Route* TrieTable::lookup(IPv4 dst) const {
    std::int32_t node = 0;
    std::int32_t best = nodes_[0].route;  // default route (/0)
    for (int i = 0; i < 32; ++i) {
        node = nodes_[node].child[(dst >> (31 - i)) & 1];
        if (node < 0) break;
        if (nodes_[node].route >= 0) best = nodes_[node].route;
    }
    return best < 0 ? nullptr : &routes_[best];
}

// ---- Rib ------------------------------------------------------------------
void Rib::add(const Route& r) { table_[r.prefix].push_back(r); }

void Rib::removeBySource(Source s) {
    for (auto it = table_.begin(); it != table_.end();) {
        auto& v = it->second;
        v.erase(std::remove_if(v.begin(), v.end(), [s](const Route& r) { return r.source == s; }), v.end());
        it = v.empty() ? table_.erase(it) : std::next(it);
    }
}

std::vector<Route> Rib::bestRoutes() const {
    std::vector<Route> out;
    out.reserve(table_.size());
    for (const auto& [prefix, candidates] : table_) {
        (void)prefix;
        out.push_back(*std::min_element(candidates.begin(), candidates.end(), [](const Route& a, const Route& b) {
            const int da = adminDistance(a.source), db = adminDistance(b.source);
            return da != db ? da < db : a.metric < b.metric;
        }));
    }
    return out;
}

std::size_t Rib::candidateCount() const {
    std::size_t n = 0;
    for (const auto& kv : table_) n += kv.second.size();
    return n;
}

}  // namespace netsim

#include "netsim/bgp.hpp"

#include <algorithm>

namespace netsim {
namespace {
std::uint32_t neighborAs(const BgpRoute& r) { return r.asPath.empty() ? 0 : r.asPath.front(); }

// Returns 0 = tie, 1 = a better, -1 = b better, for "lower is better" values.
template <typename T>
int lower(const T& a, const T& b) { return a < b ? 1 : (b < a ? -1 : 0); }
}  // namespace

BgpDecision compareRoutes(const BgpRoute& a, const BgpRoute& b, const BgpPolicy& p) {
    auto verdict = [](int c, const char* why, BgpDecision& out) {
        if (c == 0) return false;
        out = {c > 0, why};
        return true;
    };
    BgpDecision d{true, "identical attributes"};

    if (p.useLocalPref && verdict(lower(b.localPref, a.localPref), "highest LOCAL_PREF", d)) return d;
    if (p.useAsPathLength && verdict(lower(a.asPath.size(), b.asPath.size()), "shortest AS_PATH", d)) return d;
    if (p.useOrigin && verdict(lower(static_cast<int>(a.origin), static_cast<int>(b.origin)), "lowest ORIGIN", d))
        return d;
    if (p.useMed && (p.alwaysCompareMed || neighborAs(a) == neighborAs(b)) &&
        verdict(lower(a.med, b.med), "lowest MED", d))
        return d;
    if (p.preferEbgp && verdict(lower(a.ebgp ? 0 : 1, b.ebgp ? 0 : 1), "eBGP over iBGP", d)) return d;
    if (p.useIgpMetric && verdict(lower(a.igpMetric, b.igpMetric), "lowest IGP metric to next hop", d)) return d;
    if (verdict(lower(a.peerRouterId, b.peerRouterId), "lowest router-id", d)) return d;
    return d;
}

bool BgpSpeaker::receive(const BgpRoute& r) {
    if (std::find(r.asPath.begin(), r.asPath.end(), asn_) != r.asPath.end()) {
        ++rejected_;
        return false;
    }
    adjRibIn_[r.prefix].push_back(r);
    return true;
}

std::map<Prefix, BgpSelection> BgpSpeaker::selectBest() const {
    std::map<Prefix, BgpSelection> out;
    for (const auto& [prefix, candidates] : adjRibIn_) {
        BgpSelection sel;
        sel.best = candidates.front();
        sel.candidates = candidates.size();
        sel.reason = "only path";
        for (std::size_t i = 1; i < candidates.size(); ++i) {
            BgpDecision d = compareRoutes(sel.best, candidates[i], policy_);
            if (!d.firstWins) sel.best = candidates[i];
            sel.reason = d.reason;
        }
        out[prefix] = std::move(sel);
    }
    return out;
}

std::vector<Route> BgpSpeaker::toRoutes() const {
    std::vector<Route> routes;
    for (const auto& [prefix, sel] : selectBest()) {
        Route r;
        r.prefix = prefix;
        r.nextHop = sel.best.nextHop;
        r.iface = "bgp";
        r.metric = static_cast<std::uint32_t>(sel.best.asPath.size());
        r.source = sel.best.ebgp ? Source::BgpExternal : Source::BgpInternal;
        routes.push_back(r);
    }
    return routes;
}

BgpRoute BgpSpeaker::exportTo(const BgpRoute& best, IPv4 selfAddress) const {
    BgpRoute r = best;
    r.asPath.insert(r.asPath.begin(), asn_);
    r.nextHop = selfAddress;
    r.localPref = 100;  // LOCAL_PREF is not carried across eBGP
    r.ebgp = true;
    return r;
}

}  // namespace netsim

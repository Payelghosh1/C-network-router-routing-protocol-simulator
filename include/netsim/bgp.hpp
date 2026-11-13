#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "netsim/ip.hpp"
#include "netsim/routing_table.hpp"

namespace netsim {

enum class Origin : std::uint8_t { Igp = 0, Egp = 1, Incomplete = 2 };

struct BgpRoute {
    Prefix prefix;
    IPv4 nextHop = 0;
    std::uint32_t localPref = 100;
    std::vector<std::uint32_t> asPath;
    Origin origin = Origin::Igp;
    std::uint32_t med = 0;
    bool ebgp = true;                // learned from an external peer?
    std::uint32_t igpMetric = 0;     // cost to reach nextHop inside the AS
    IPv4 peerRouterId = 0;           // final tie-breaker
};

// Each step of the decision process can be switched off, so you can show how the outcome changes.
struct BgpPolicy {
    bool useLocalPref = true;
    bool useAsPathLength = true;
    bool useOrigin = true;
    bool useMed = true;
    bool alwaysCompareMed = false;  // default: MED only compared between routes from the same neighbour AS
    bool preferEbgp = true;
    bool useIgpMetric = true;
};

struct BgpDecision {
    bool firstWins;
    std::string reason;
};

// Pairwise comparison implementing the (simplified) BGP best-path algorithm:
//  1 highest LOCAL_PREF  2 shortest AS_PATH  3 lowest ORIGIN  4 lowest MED
//  5 eBGP over iBGP      6 lowest IGP metric 7 lowest peer router-id
BgpDecision compareRoutes(const BgpRoute& a, const BgpRoute& b, const BgpPolicy& policy);

struct BgpSelection {
    BgpRoute best;
    std::size_t candidates = 0;
    std::string reason;  // which rule decided the final comparison
};

class BgpSpeaker {
public:
    BgpSpeaker(std::uint32_t asn, IPv4 routerId, BgpPolicy policy = {})
        : asn_(asn), routerId_(routerId), policy_(policy) {}

    // Returns false (and counts a rejection) if our own ASN is already in the AS_PATH (loop prevention).
    bool receive(const BgpRoute& r);

    std::map<Prefix, BgpSelection> selectBest() const;
    std::vector<Route> toRoutes() const;  // ready to hand to Router::replaceRoutes

    // What we would announce to an eBGP neighbour: prepend our ASN, next-hop-self, reset LOCAL_PREF.
    BgpRoute exportTo(const BgpRoute& best, IPv4 selfAddress) const;

    std::uint32_t asn() const { return asn_; }
    std::size_t rejected() const { return rejected_; }
    const BgpPolicy& policy() const { return policy_; }

private:
    std::uint32_t asn_;
    IPv4 routerId_;
    BgpPolicy policy_;
    std::map<Prefix, std::vector<BgpRoute>> adjRibIn_;
    std::size_t rejected_ = 0;
};

}  // namespace netsim

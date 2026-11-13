#pragma once
#include <map>
#include <string>
#include <vector>

#include "netsim/pcap.hpp"
#include "netsim/router.hpp"

namespace netsim {

struct Link {
    std::string a, b;
    std::uint32_t cost = 1;
    bool up = true;
};

struct TraceHop {
    std::string router;
    Verdict verdict;
    std::string detail;
};

struct TraceResult {
    std::vector<TraceHop> hops;
    bool delivered = false;
    std::string outcome;
};

struct OspfRunStats {
    std::size_t lsaMessages = 0;  // every LSA delivery during flooding
    std::size_t spfRuns = 0;
};

// A set of routers joined by point-to-point links, plus a tiny OSPF engine:
// originate LSAs -> reliable flooding -> Dijkstra on every router -> install routes.
class Network {
public:
    Router& addRouter(const std::string& name, const std::string& routerId,
                      Router::FibType fib = Router::FibType::Trie);
    void addNetwork(const std::string& router, const std::string& prefix);  // connected LAN
    void addLink(const std::string& a, const std::string& b, std::uint32_t cost);
    bool setLinkState(const std::string& a, const std::string& b, bool up);

    // (Re)converge OSPF. Call again after any topology change.
    OspfRunStats runOspf();

    // Inject a packet at `src` and follow it hop by hop. Optionally capture every hop to a pcap.
    TraceResult trace(const std::string& src, std::vector<std::uint8_t> packet, PcapWriter* pcap = nullptr,
                      int maxHops = 32);

    Router& router(const std::string& name) { return routers_.at(name); }
    const Router& router(const std::string& name) const { return routers_.at(name); }
    const std::vector<Link>& links() const { return links_; }

private:
    std::vector<std::string> upNeighbors(const std::string& name) const;
    const Link* findLink(const std::string& a, const std::string& b) const;

    std::map<std::string, Router> routers_;
    std::map<IPv4, std::string> idToName_;
    std::map<std::string, std::uint32_t> lsaSeq_;
    std::vector<Link> links_;
};

}  // namespace netsim

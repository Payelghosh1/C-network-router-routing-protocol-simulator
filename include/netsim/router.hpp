#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "netsim/ospf.hpp"
#include "netsim/packet.hpp"
#include "netsim/routing_table.hpp"

namespace netsim {

enum class Verdict { Forwarded, DeliveredLocal, DroppedMalformed, DroppedTtl, DroppedNoRoute };
const char* toString(Verdict v);

struct ForwardResult {
    Verdict verdict = Verdict::DroppedMalformed;
    ParseError error = ParseError::None;
    const Route* route = nullptr;  // valid for Forwarded; points into the FIB
};

struct RouterStats {
    std::uint64_t received = 0, forwarded = 0, delivered = 0;
    std::uint64_t droppedMalformed = 0, droppedTtl = 0, droppedNoRoute = 0;
};

// A router = control plane (RIB + OSPF LSDB) feeding a data plane (FIB + process()).
class Router {
public:
    enum class FibType { Trie, Linear };

    Router(std::string name, IPv4 id, FibType type = FibType::Trie);

    const std::string& name() const { return name_; }
    IPv4 id() const { return id_; }

    // ---- control plane ----
    void addConnected(const Prefix& p, const std::string& iface = "lan0");
    void addStatic(const Prefix& p, IPv4 nextHop, const std::string& iface, std::uint32_t metric = 0);
    // Remove every route from the given protocols, add `routes`, then rebuild the FIB once.
    void replaceRoutes(const std::vector<Source>& sources, const std::vector<Route>& routes);
    void rebuildFib();

    const std::vector<Prefix>& connected() const { return connected_; }
    Lsdb& lsdb() { return lsdb_; }
    const Lsdb& lsdb() const { return lsdb_; }
    const Rib& rib() const { return rib_; }
    const RoutingTable& fib() const { return *fib_; }

    // ---- data plane ----
    // Validate header, check TTL, longest-prefix-match, decrement TTL in place. No allocations.
    ForwardResult process(std::uint8_t* data, std::size_t len);
    ForwardResult process(std::vector<std::uint8_t>& bytes) { return process(bytes.data(), bytes.size()); }

    const RouterStats& stats() const { return stats_; }

private:
    std::string name_;
    IPv4 id_;
    std::unique_ptr<RoutingTable> fib_;
    Rib rib_;
    Lsdb lsdb_;
    std::vector<Prefix> connected_;
    RouterStats stats_;
};

}  // namespace netsim

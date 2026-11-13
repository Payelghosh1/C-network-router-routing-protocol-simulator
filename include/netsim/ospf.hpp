#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "netsim/ip.hpp"
#include "netsim/routing_table.hpp"

namespace netsim {

// Simplified Router-LSA: who I am, who my neighbours are (and at what cost), what networks I own.
struct LsaLink {
    std::string neighbor;
    std::uint32_t cost;
};

struct Lsa {
    std::string origin;
    IPv4 address = 0;  // router-id / address used as next hop by neighbours
    std::uint32_t seq = 0;
    std::vector<LsaLink> links;
    std::vector<Prefix> networks;
};

// Link-state database: keeps the newest LSA (highest sequence number) per originating router.
class Lsdb {
public:
    bool install(const Lsa& lsa);  // true if new/newer (=> must be flooded onward)
    const Lsa* find(const std::string& origin) const;
    std::size_t size() const { return db_.size(); }
    const std::map<std::string, Lsa>& all() const { return db_; }

private:
    std::map<std::string, Lsa> db_;
};

struct SpfEntry {
    std::uint32_t cost = 0;
    std::string firstHop;  // neighbour of `self` on the shortest path ("" for self)
};

// Dijkstra over the LSDB. An edge u->v is only used if v's LSA also lists u (two-way check),
// exactly like OSPF's bidirectional connectivity check. Ties are broken deterministically.
std::map<std::string, SpfEntry> computeSpf(const Lsdb& db, const std::string& self);

// Turn SPF results into routes: one per network advertised by every reachable remote router.
std::vector<Route> routesFromSpf(const Lsdb& db, const std::string& self,
                                 const std::map<std::string, SpfEntry>& spf);

}  // namespace netsim

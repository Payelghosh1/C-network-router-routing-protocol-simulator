#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "netsim/ip.hpp"

namespace netsim {

enum class Source { Connected, Static, BgpExternal, Ospf, BgpInternal };
const char* toString(Source s);
int adminDistance(Source s);  // Cisco-style defaults: 0, 1, 20, 110, 200

struct Route {
    Prefix prefix;
    IPv4 nextHop = 0;  // 0 => directly connected
    std::string iface;
    std::uint32_t metric = 0;
    Source source = Source::Static;
};

// ---------------------------------------------------------------------------
// FIB interface. Both implementations answer "longest prefix match".
// insert() replaces any existing route for the exact same prefix.
// lookup() returns a pointer valid until the next mutation (no copies on the hot path).
// ---------------------------------------------------------------------------
class RoutingTable {
public:
    virtual ~RoutingTable() = default;
    virtual void insert(const Route& r) = 0;
    virtual const Route* lookup(IPv4 dst) const = 0;
    virtual std::size_t size() const = 0;
    virtual void clear() = 0;
    virtual std::vector<Route> routes() const = 0;
    virtual const char* name() const = 0;
};

// O(n) scan. The baseline that the trie is benchmarked against.
// Duplicate prefixes are not de-duplicated; for equal prefix lengths the newest entry wins.
class LinearTable final : public RoutingTable {
public:
    void insert(const Route& r) override { routes_.push_back(r); }
    const Route* lookup(IPv4 dst) const override;
    std::size_t size() const override { return routes_.size(); }
    void clear() override { routes_.clear(); }
    std::vector<Route> routes() const override { return routes_; }
    const char* name() const override { return "linear"; }

private:
    std::vector<Route> routes_;
};

// Binary (unibit) trie over the destination address; lookup is O(32) regardless of table size.
// Nodes live in one contiguous vector and reference each other by index (cache-friendlier than
// pointer-chasing, trivially copyable, no per-node allocation).
class TrieTable final : public RoutingTable {
public:
    TrieTable() { clear(); }
    void insert(const Route& r) override;
    const Route* lookup(IPv4 dst) const override;
    std::size_t size() const override { return routes_.size(); }
    void clear() override;
    std::vector<Route> routes() const override { return routes_; }
    const char* name() const override { return "trie"; }
    std::size_t nodeCount() const { return nodes_.size(); }

private:
    struct Node {
        std::int32_t child[2] = {-1, -1};
        std::int32_t route = -1;  // index into routes_
    };
    std::vector<Node> nodes_;
    std::vector<Route> routes_;
};

// ---------------------------------------------------------------------------
// RIB: keeps every candidate route per prefix (from every protocol) and picks the best by
// administrative distance, then metric. The FIB is rebuilt from bestRoutes().
// ---------------------------------------------------------------------------
class Rib {
public:
    void add(const Route& r);
    void removeBySource(Source s);
    std::vector<Route> bestRoutes() const;
    std::size_t candidateCount() const;

private:
    std::map<Prefix, std::vector<Route>> table_;
};

}  // namespace netsim

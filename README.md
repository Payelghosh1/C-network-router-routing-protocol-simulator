# netsim — C++ Network Router & Routing Protocol Simulator

A software router written in modern C++17 that models the two halves of a real router:

* **Data plane** – validates IPv4 headers, checks/decrements TTL with an incremental checksum update,
  and forwards using **longest-prefix match** on a **binary trie** (with a linear-scan baseline to benchmark against).
* **Control plane** – a **RIB** that arbitrates between connected / static / BGP / OSPF routes by
  *administrative distance*, an **OSPF-style link-state engine** (LSA flooding + Dijkstra SPF + reconvergence),
  and a **BGP best-path selection** engine with configurable decision steps.

Packets can be traced hop-by-hop across a simulated topology and exported to a `.pcap` that opens in **Wireshark**.

```
include/netsim/
  ip.hpp             IPv4 parsing, CIDR Prefix
  packet.hpp         IPv4 header parse/serialize, RFC 1071 checksum, RFC 1141 TTL update
  routing_table.hpp  RoutingTable interface, LinearTable, TrieTable, Rib (admin distance)
  ospf.hpp           LSA, LSDB, Dijkstra SPF (two-way check), route generation
  bgp.hpp            BGP attributes, 7-step decision process, BgpSpeaker (loop prevention, export)
  router.hpp         Router = RIB + FIB + process() forwarding path
  network.hpp        Topology, LSA flooding, OSPF convergence, packet tracing, pcap capture
  pcap.hpp           libpcap-format writer (LINKTYPE_RAW)
src/                 implementations
apps/demo.cpp        guided end-to-end walkthrough
apps/benchmark.cpp   linear vs trie lookup + forwarding throughput
tests/               57 GoogleTest cases
```

## Build & run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure   # unit tests (GoogleTest is fetched automatically)
./build/netsim_demo                          # OSPF convergence, failover, BGP; writes demo.pcap
./build/netsim_bench                         # benchmark (optional arg: max table size, default 100000)
```

Options: `-DNETSIM_BUILD_TESTS=OFF` (skip GoogleTest), `-DNETSIM_SANITIZE=ON` (ASan + UBSan, use with `Debug`).
Requires a C++17 compiler and CMake ≥ 3.16.

## Results (my machine, GCC 13, -O2)

| routes  | linear ns/lookup | trie ns/lookup | speed-up |
|--------:|-----------------:|---------------:|---------:|
| 1,000   | 812              | 46             | 17x      |
| 10,000  | 7,829            | 71             | 111x     |
| 100,000 | 244,858          | 177            | 1,382x   |

Full forwarding path (parse + validate + LPM + TTL/checksum) on a 100k-route FIB: ~205 ns/packet (~4.9 Mpps)
single-threaded with the trie. Absolute numbers depend on your CPU; the *shape* (linear grows with n, trie stays ~flat) is the point.
The benchmark cross-checks trie vs linear results before timing, and aborts on any mismatch.

## Design decisions worth knowing (good interview material)

* **Trie nodes live in a `std::vector` and use integer indices**, not pointers: one contiguous allocation,
  better cache behaviour, no per-node `new`. Lookup is O(32) regardless of table size.
* **`lookup()` returns `const Route*`**, not a copy: no allocation or string copy on the hot path.
  `Router::process()` works in place on the raw buffer with zero heap allocation.
* **Incremental checksum (RFC 1141)** instead of recomputing the header checksum after TTL--; a test verifies
  20,000 random packets still validate afterwards.
* **RIB → FIB split.** Every protocol installs candidate routes in the RIB; the FIB is rebuilt from the winners
  (lowest admin distance, then metric). Withdrawing a better route automatically falls back to the next best one.
* **OSPF two-way check.** An edge is only used by SPF if both routers' LSAs list each other, so stale LSAs from
  partitioned/dead routers can't create phantom paths. LSAs carry sequence numbers; only newer ones are re-flooded.
* **Deterministic tie-breaking** in SPF (equal cost → lexicographically smaller neighbour) so tests are stable.
* **BGP MED gotcha is modelled:** MED is only compared between routes from the *same neighbour AS* unless
  `alwaysCompareMed` is set (see `BgpDecision.MedOnlyComparedWithinSameNeighborAs`). The demo shows it in action.
* **Testing strategy:** unit tests per layer, plus a *property test* (random tables, trie must equal the linear scan).

## Wireshark

`netsim_demo` writes `demo.pcap` (raw IPv4). Open it in Wireshark and watch the TTL fall hop by hop and the
header checksum stay valid; the second half of the capture shows the detour after the link failure.

## Debugging with GDB

```bash
cmake -S . -B build-dbg -DCMAKE_BUILD_TYPE=Debug && cmake --build build-dbg -j
gdb --args ./build-dbg/netsim_demo
(gdb) break netsim::Router::process
(gdb) run
(gdb) print h            # decoded IPv4 header after parseHeader
(gdb) finish
```

## Known simplifications (be upfront about these)

* Point-to-point links with a single OSPF area; no DR/BDR election, Hellos, LSA aging or Network-LSAs.
  Convergence is computed by an instantaneous flood, not simulated in time (so there is no convergence *time*, only message count).
* One best path per prefix (no ECMP). BGP has no sessions/FSM/UPDATE wire format; it's the path-selection logic, loop
  prevention and export rules only. IPv4 only, no fragmentation, no ICMP generation (the code marks where it would go).
* The trie is a unibit trie. A production FIB would use a multibit/compressed trie (DIR-24-8, LC-trie, Poptrie).

## Ideas to extend it

1. ECMP in SPF + hash-based next-hop selection  2. LC-trie / DIR-24-8 and compare in the benchmark
3. Multi-threaded forwarding with a lock-free / RCU-style FIB swap  4. OSPF Hello/dead timers on a discrete-event clock
5. ICMP Time Exceeded / Unreachable  6. Real `AF_PACKET`/TUN packet I/O on Linux  7. IPv6 (128-bit trie)

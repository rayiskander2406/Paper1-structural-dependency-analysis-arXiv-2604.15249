"""
Netlist Adapter — Yosys JSON to Z3 Expression Converter

Converts gate-level netlists (Yosys JSON format) into per-wire Z3 expressions
compatible with ProbingVerifier.check_masked_wire() and check_unmasked_wire().

M4a deliverable per M4 Scope v1.0 (Grok-audited).

Pipeline:
    RTL → sv2v → Yosys (synth -flatten; techmap; dffunmap; opt)
        → write_json → NetlistAdapter → wire_fn → ProbingVerifier

Design decisions (from M4 scope):
    D1: DFF outputs (Q pins) are free variables (combinational cut points)
    D2: Input labeling via standalone JSON config
    D6: Unknown cell types raise EncodingError (black-box detection, M0 §2.2)

References:
    - M0 Spec: .claude/research/M0_FORMAL_SPECIFICATION.md
    - M4 Scope: .claude/research/M4_SCOPE.md
"""

from __future__ import annotations

import json
import logging
import multiprocessing
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from .probing_verifier import (
    DependencyResult,
    EncodingError,
    ProbingVerifier,
    SecurityVerdict,
    WireSecurityResult,
)

logger = logging.getLogger(__name__)

# Gate-level cell types after Yosys techmap + dffunmap
# Combinational gates (extended set for MC-FM forward compatibility)
_COMB_CELLS = {
    "$_AND_", "$_OR_", "$_XOR_", "$_NOT_", "$_MUX_",
    "$_NAND_", "$_NOR_", "$_XNOR_",
    "$_ANDNOT_", "$_ORNOT_",
    "$_AOI3_", "$_OAI3_",
    "$_AOI4_", "$_OAI4_",
}

# All DFF variants from dffunmap: $_DFF_{CEdge}{REdge}{ResetVal}_
# C=clock edge (P/N), R=reset edge (P/N), V=reset value (0/1)
_DFF_CELLS = {
    "$_DFF_P_",
    "$_DFF_N_",
    "$_DFF_PP0_",
    "$_DFF_PP1_",
    "$_DFF_PN0_",
    "$_DFF_PN1_",
    "$_DFF_NP0_",
    "$_DFF_NP1_",
    "$_DFF_NN0_",
    "$_DFF_NN1_",
}

ALLOWED_CELLS = frozenset(_COMB_CELLS | _DFF_CELLS)

# Yosys metadata cells to silently skip (not real logic)
_METADATA_CELLS = {"$scopeinfo"}


# =============================================================================
# MC-FM Utility Functions (module-level for direct testing)
# =============================================================================


def _collect_free_vars(expr) -> set:
    """Collect all free BitVec variables in a Z3 expression.

    Walks the expression DAG exactly once using an explicit stack.
    Returns set of Z3 variable references (for identity comparison via get_id()).

    Cost: O(|DAG nodes|). With Z3 hash consing, shared sub-expressions
    are visited once. See MC-FM Scope v0.5 §2.6.2.
    """
    import z3 as z3mod

    seen: set[int] = set()
    result: set = set()
    stack = [expr]
    while stack:
        e = stack.pop()
        eid = e.get_id()
        if eid in seen:
            continue
        seen.add(eid)
        if z3mod.is_const(e) and e.decl().kind() == z3mod.Z3_OP_UNINTERPRETED:
            result.add(e)
        else:
            stack.extend(e.children())
    return result


def _expr_node_count(expr) -> int:
    """Count unique DAG nodes in Z3 expression. O(|DAG|).

    Used by per-DFF size guard to detect expression blowup.
    See MC-FM Scope v0.5 §2.6.2.
    """
    seen: set[int] = set()
    stack = [expr]
    while stack:
        e = stack.pop()
        eid = e.get_id()
        if eid in seen:
            continue
        seen.add(eid)
        stack.extend(e.children())
    return len(seen)


def _expr_contains_var(expr, var) -> bool:
    """Check if Z3 expression contains free variable.

    Uses Z3's substitute (O(n) with hash consing).
    See MC-FM Scope v0.5 §2.6.2.
    """
    import z3 as z3mod

    sentinel = z3mod.BitVecVal(0, var.size())
    substituted = z3mod.substitute(expr, (var, sentinel))
    return not expr.eq(substituted)


def _exprs_equal(a, b) -> bool:
    """Structural equality check for Z3 expressions."""
    return a.eq(b)


def _tarjan_scc(adj: dict[str, set[str]]) -> list[set[str]]:
    """Iterative Tarjan's strongly connected components algorithm.

    Uses an explicit work stack instead of recursion.
    Safe for graphs with 100K+ nodes (no RecursionError, no stack overflow).

    Args:
        adj: Adjacency dict mapping node -> set of successors.
             Self-edges are valid and handled correctly.

    Returns:
        List of SCCs (sets of node names). Nodes not in any cycle
        appear as singleton SCCs with no self-edge.

    See MC-FM Scope v0.5 §2.6.3.
    """
    index_map: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: list[set[str]] = []
    counter = 0

    for start in adj:
        if start in index_map:
            continue

        # Work stack: (node, neighbor_iterator, is_entry)
        work: list[tuple[str, Any, bool]] = [
            (start, iter(sorted(adj.get(start, set()))), True)
        ]

        while work:
            v, neighbors, is_entry = work[-1]

            if is_entry:
                index_map[v] = counter
                lowlink[v] = counter
                counter += 1
                stack.append(v)
                on_stack.add(v)
                work[-1] = (v, neighbors, False)

            found_unvisited = False
            for w in neighbors:
                if w not in index_map:
                    work.append(
                        (w, iter(sorted(adj.get(w, set()))), True)
                    )
                    found_unvisited = True
                    break
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], index_map[w])

            if not found_unvisited:
                if lowlink[v] == index_map[v]:
                    scc: set[str] = set()
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        scc.add(w)
                        if w == v:
                            break
                    result.append(scc)

                work.pop()
                if work:
                    parent_v = work[-1][0]
                    lowlink[parent_v] = min(lowlink[parent_v], lowlink[v])

    return result


class NetlistAdapter:
    """Convert Yosys JSON netlist to per-wire Z3 expressions.

    Usage:
        adapter = NetlistAdapter("module.json", {
            "mode": "masked",
            "s0_bits": {"x": [0], "y": [0]},
            "s1_bits": {"x": [1], "y": [1]},
            "r_bits": {"rnd": [0]},
            "p_bits": {"clk": [0], "rst_n": [0], "zeroize": [0]},
        })

        wire_fn = adapter.build_wire_fn(net_id=20)
        result = verifier.check_masked_wire(
            wire_fn, adapter.s0_width, adapter.s1_width,
            adapter.r_width, adapter.p_width,
        )
    """

    def __init__(
        self,
        netlist: str | Path | dict,
        labeling: dict[str, Any],
        module_name: str | None = None,
        *,
        multi_cycle: bool = False,
        mc_max_depth: int | None = None,
        mc_fm_max_propagate: int = 50_000,
        mc_fm_max_expr_nodes: int = 100_000,
        mc_fm_max_layers: int = 50,
    ):
        """
        Args:
            netlist: Yosys JSON dict, or path to JSON file.
            labeling: Input grouping config.
            module_name: Which module to analyze (default: first in JSON).
        """
        if isinstance(netlist, (str, Path)):
            with open(netlist) as f:
                netlist = json.load(f)

        modules = netlist.get("modules", {})
        if not modules:
            raise EncodingError("No modules in netlist JSON")

        if module_name:
            if module_name not in modules:
                raise EncodingError(
                    f"Module '{module_name}' not found in netlist"
                )
            self._module_name = module_name
        else:
            self._module_name = next(iter(modules))

        self._module = modules[self._module_name]
        self._ports = self._module.get("ports", {})
        # Filter out Yosys metadata cells ($scopeinfo etc.) — not real logic
        self._cells = {
            n: c
            for n, c in self._module.get("cells", {}).items()
            if c["type"] not in _METADATA_CELLS
        }
        self._netnames = self._module.get("netnames", {})
        self.mode = labeling.get("mode", "masked")

        self._validate_cells()

        # Resolve labeling → net IDs per group
        self._s0_nets: list[int] = []
        self._s1_nets: list[int] = []
        self._r_nets: list[int] = []
        self._p_nets: list[int] = []
        self._s_nets: list[int] = []

        if self.mode == "masked":
            self._s0_nets = self._resolve_bits(labeling.get("s0_bits", {}))
            self._s1_nets = self._resolve_bits(labeling.get("s1_bits", {}))
            self._r_nets = self._resolve_bits(labeling.get("r_bits", {}))
            self._p_nets = self._resolve_bits(labeling.get("p_bits", {}))
        else:
            self._s_nets = self._resolve_bits(labeling.get("s_bits", {}))
            self._p_nets = self._resolve_bits(labeling.get("p_bits", {}))

        self._validate_labeling()

        # DFF Q outputs → free variables (combinational cut points, D1)
        self._dff_q_nets: list[tuple[str, int]] = []
        # MC-D1: DFF D→Q pairs for multi-cycle propagation
        self._dff_pairs: list[tuple[str, int | str, int]] = []
        for name, cell in self._cells.items():
            if cell["type"] in _DFF_CELLS:
                d_net = cell["connections"]["D"][0]
                q_net = cell["connections"]["Q"][0]
                self._dff_q_nets.append((name, q_net))
                self._dff_pairs.append((name, d_net, q_net))

        # Producer map: net_id → cell_name (combinational cells only)
        # Detect multi-driver nets (Grok M4a Q5 + M4 audit Q10)
        # Checks both combinational cells AND DFF Q outputs for conflicts.
        self._net_producer: dict[int, str] = {}
        all_driven: dict[int, str] = {}  # net_id → driver description

        # DFF Q outputs
        for dff_name, q_net in self._dff_q_nets:
            if isinstance(q_net, int):
                all_driven[q_net] = f"DFF '{dff_name}' Q"

        # Combinational cells
        for name, cell in self._cells.items():
            if cell["type"] in _DFF_CELLS:
                continue
            y_net = cell["connections"]["Y"][0]
            if isinstance(y_net, int):
                if y_net in all_driven:
                    raise EncodingError(
                        f"Multiple drivers for net {y_net}: "
                        f"{all_driven[y_net]} and cell '{name}'"
                    )
                all_driven[y_net] = f"cell '{name}'"
                self._net_producer[y_net] = name

        self._topo_order = self._topological_sort()
        self._wire_names = self._build_wire_name_map()
        self._z3 = None

        # Pre-allocate DFF free variables (SIGNIFICANT fix, Grok M4a audit)
        # Avoids re-creating z3.BitVec objects on every _build_expressions call
        self._dff_vars: dict[int, Any] = {}
        if self._dff_q_nets:
            z3 = self._ensure_z3()
            for i, (_cell_name, q_net) in enumerate(self._dff_q_nets):
                self._dff_vars[q_net] = z3.BitVec(f"__dff_{i}", 1)

        # Pre-allocate per-bit randomness variables (RD-01)
        # Each r net gets its own BitVec("r_i", 1) for reliable z3.substitute()
        # (Grok v0.1 AV6+AV9: Extract-based substitution is unreliable)
        self._r_bit_vars: dict[int, Any] = {}
        if self._r_nets:
            z3 = self._ensure_z3()
            for i, net_id in enumerate(self._r_nets):
                self._r_bit_vars[net_id] = z3.BitVec(f"r_{i}", 1)

        # Multi-cycle mode (MC-D1)
        self._multi_cycle = multi_cycle
        self._mc_iterations: int = 0  # Filled by _compute_input_deps_mc()
        if mc_max_depth is not None and mc_max_depth < 0:
            raise ValueError(
                f"mc_max_depth must be non-negative or None, got {mc_max_depth}"
            )
        self._mc_max_depth = mc_max_depth
        self._mc_fm_max_propagate = mc_fm_max_propagate
        self._mc_fm_max_expr_nodes = mc_fm_max_expr_nodes
        self._mc_fm_max_layers = mc_fm_max_layers

        # Fan-in dependency sets: net_id → set of input groups in fan-in
        # Computed once in O(cells), used for constant-net filtering (M4b)
        if multi_cycle:
            self._input_deps, self._r_input_deps = (
                self._compute_input_deps_mc()
            )
        else:
            self._input_deps, self._r_input_deps = (
                self._compute_input_deps()
            )

    # ─── Properties ──────────────────────────────────────────────────

    @property
    def module_name(self) -> str:
        return self._module_name

    @property
    def s0_width(self) -> int:
        return len(self._s0_nets)

    @property
    def s1_width(self) -> int:
        return len(self._s1_nets)

    @property
    def r_width(self) -> int:
        return len(self._r_nets)

    @property
    def p_width(self) -> int:
        return len(self._p_nets)

    @property
    def s_width(self) -> int:
        return len(self._s_nets)

    @property
    def cell_count(self) -> int:
        return len(self._cells)

    @property
    def combinational_cell_count(self) -> int:
        return len(self._topo_order)

    @property
    def dff_count(self) -> int:
        return len(self._dff_q_nets)

    @property
    def is_multi_cycle(self) -> bool:
        return self._multi_cycle

    @property
    def mc_iteration_count(self) -> int:
        """Number of Jacobi iterations MC-D1 performed before converging.

        Returns 0 for single-cycle mode or if multi-cycle was not used.
        Each iteration corresponds to one DFF D→Q propagation step
        (one clock-cycle boundary crossing in the dependency model).
        """
        return self._mc_iterations

    # ─── DFF Chain Depth Analysis ────────────────────────────────────

    def compute_dff_chain_depth(self) -> dict[str, Any]:
        """Compute the DFF chain depth (longest DFF→DFF path in the netlist).

        Builds a DFF-level graph: each DFF is a node, and there is an edge
        from DFF_A to DFF_B if DFF_A's Q output is in DFF_B's D-pin
        combinational fan-in cone.

        Returns dict with:
          - depth: longest acyclic DFF→DFF path length (in DFF hops)
          - has_feedback: True if any DFF feedback cycles exist
          - feedback_sccs: list of SCC sets (each with >1 DFF or self-loop)
          - longest_acyclic_path: same as depth (for clarity)
          - dff_count: total DFFs in the module
          - pi_to_dff_max: max depth from primary inputs to any DFF
        """
        if not self._dff_pairs:
            return {
                "depth": 0,
                "has_feedback": False,
                "feedback_sccs": [],
                "longest_acyclic_path": 0,
                "dff_count": 0,
                "pi_to_dff_max": 0,
            }

        # Step 1: For each DFF, find which other DFFs are in its D-pin
        # combinational fan-in. Use the combinational topo order + producer map.

        # Build net → producing DFF map (Q outputs)
        q_net_to_dff: dict[int, str] = {}
        dff_d_nets: dict[str, int | str] = {}
        for dff_name, d_net, q_net in self._dff_pairs:
            q_net_to_dff[q_net] = dff_name
            dff_d_nets[dff_name] = d_net

        # Build combinational fan-in for each net: which DFF Q outputs
        # are reachable through combinational logic only.
        # We propagate "which DFFs feed this net" through topo order.
        net_dff_fanin: dict[int | str, frozenset[str]] = {}

        # Initialize: DFF Q outputs are sourced by their own DFF
        for q_net, dff_name in q_net_to_dff.items():
            net_dff_fanin[q_net] = frozenset({dff_name})

        # Primary inputs have no DFF fan-in
        for net_id in (
            self._s0_nets + self._s1_nets + self._r_nets
            + self._p_nets + self._s_nets
        ):
            net_dff_fanin.setdefault(net_id, frozenset())

        # Constants
        net_dff_fanin["0"] = frozenset()
        net_dff_fanin["1"] = frozenset()
        net_dff_fanin["x"] = frozenset()

        # Propagate through combinational cells in topo order
        for cell_name in self._topo_order:
            cell = self._cells[cell_name]
            conn = cell["connections"]
            y_net = conn["Y"][0]

            combined: set[str] = set()
            for pin, net_ids in conn.items():
                if pin == "Y":
                    continue
                for nid in net_ids:
                    combined |= net_dff_fanin.get(nid, frozenset())

            net_dff_fanin[y_net] = frozenset(combined)

        # Step 2: Build DFF-level adjacency graph
        # Edge: DFF_A → DFF_B means DFF_A's Q is in DFF_B's D fan-in
        adj: dict[str, set[str]] = {
            dff_name: set() for dff_name, _, _ in self._dff_pairs
        }
        for dff_name, d_net, _q_net in self._dff_pairs:
            source_dffs = net_dff_fanin.get(d_net, frozenset())
            for src_dff in source_dffs:
                adj[src_dff].add(dff_name)

        # Step 3: Detect feedback cycles using Tarjan's SCC
        sccs = _tarjan_scc(adj)
        feedback_sccs = []
        for scc in sccs:
            if len(scc) > 1:
                feedback_sccs.append(scc)
            elif len(scc) == 1:
                node = next(iter(scc))
                if node in adj.get(node, set()):
                    feedback_sccs.append(scc)  # Self-loop

        # Step 4: Compute longest acyclic path via DAG longest-path
        # Condense SCCs into super-nodes for the DAG
        node_to_scc: dict[str, int] = {}
        for i, scc in enumerate(sccs):
            for node in scc:
                node_to_scc[node] = i

        # Build condensed DAG
        n_sccs = len(sccs)
        cond_adj: dict[int, set[int]] = {i: set() for i in range(n_sccs)}
        for src_dff, targets in adj.items():
            src_scc = node_to_scc[src_dff]
            for tgt_dff in targets:
                tgt_scc = node_to_scc[tgt_dff]
                if src_scc != tgt_scc:
                    cond_adj[src_scc].add(tgt_scc)

        # Topological sort of condensed DAG (Kahn's algorithm)
        in_degree = {i: 0 for i in range(n_sccs)}
        for src, tgts in cond_adj.items():
            for tgt in tgts:
                in_degree[tgt] += 1

        queue = deque(i for i in range(n_sccs) if in_degree[i] == 0)
        cond_topo: list[int] = []
        while queue:
            node = queue.popleft()
            cond_topo.append(node)
            for tgt in cond_adj[node]:
                in_degree[tgt] -= 1
                if in_degree[tgt] == 0:
                    queue.append(tgt)

        # Longest path in condensed DAG
        dist: dict[int, int] = {i: 0 for i in range(n_sccs)}
        for node in cond_topo:
            for tgt in cond_adj[node]:
                if dist[tgt] < dist[node] + 1:
                    dist[tgt] = dist[node] + 1

        longest_acyclic = max(dist.values()) if dist else 0

        # PI-to-DFF max: how many DFF layers from primary inputs
        # (same as longest_acyclic for most designs, but computed
        # from sources — SCCs with in-degree 0 in condensed DAG)
        pi_to_dff_max = longest_acyclic

        return {
            "depth": longest_acyclic,
            "has_feedback": len(feedback_sccs) > 0,
            "feedback_sccs": feedback_sccs,
            "longest_acyclic_path": longest_acyclic,
            "dff_count": len(self._dff_pairs),
            "pi_to_dff_max": pi_to_dff_max,
        }

    # ─── Fan-in Dependency Analysis ──────────────────────────────────

    def _compute_input_deps(
        self,
    ) -> tuple[dict[int | str, frozenset[str]], dict[int | str, frozenset[int]]]:
        """Compute which input groups are in each net's fan-in cone.

        Propagates through the topological order in O(cells) total.
        Used by has_share_dependency() for constant-net filtering.

        Returns:
            (share_deps, r_deps) where:
            - share_deps: net_id → frozenset of group labels ("s0", "s1", "r", ...)
            - r_deps: net_id → frozenset of randomness bit indices in fan-in (RD-01)
        """
        deps: dict[int | str, frozenset[str]] = {}
        r_deps: dict[int | str, frozenset[int]] = {}

        # Constants (Yosys: "0" = logic 0, "1" = logic 1, "x" = don't-care)
        deps["0"] = frozenset()
        deps["1"] = frozenset()
        deps["x"] = frozenset()
        r_deps["0"] = frozenset()
        r_deps["1"] = frozenset()
        r_deps["x"] = frozenset()

        # Primary inputs
        _empty_r: frozenset[int] = frozenset()
        for net_id in self._s0_nets:
            deps[net_id] = frozenset({"s0"})
            r_deps[net_id] = _empty_r
        for net_id in self._s1_nets:
            deps[net_id] = frozenset({"s1"})
            r_deps[net_id] = _empty_r
        for i, net_id in enumerate(self._r_nets):
            deps[net_id] = frozenset({"r"})
            r_deps[net_id] = frozenset({i})  # RD-01: this net IS r_i
        for net_id in self._s_nets:
            deps[net_id] = frozenset({"s"})
            r_deps[net_id] = _empty_r
        for net_id in self._p_nets:
            deps.setdefault(net_id, frozenset({"p"}))
            r_deps.setdefault(net_id, _empty_r)

        # DFF Q outputs — no current-cycle input deps (cut points)
        for _name, q_net in self._dff_q_nets:
            deps[q_net] = frozenset({"dff"})
            r_deps[q_net] = _empty_r

        # Propagate through combinational cells in topological order
        self._propagate_deps(deps, r_deps)

        return deps, r_deps

    def _propagate_deps(
        self,
        deps: dict[int | str, frozenset[str]],
        r_deps: dict[int | str, frozenset[int]],
    ) -> None:
        """Single combinational pass: propagate deps through topo order.

        Shared by both single-cycle and multi-cycle dep computation.
        """
        for cell_name in self._topo_order:
            cell = self._cells[cell_name]
            conn = cell["connections"]
            y_net = conn["Y"][0]

            combined: set[str] = set()
            combined_r: set[int] = set()
            for pin, net_ids in conn.items():
                if pin == "Y":
                    continue
                for nid in net_ids:
                    if nid in deps:
                        combined |= deps[nid]
                    if nid in r_deps:
                        combined_r |= r_deps[nid]

            deps[y_net] = frozenset(combined)
            r_deps[y_net] = frozenset(combined_r)

    def _compute_input_deps_mc(
        self,
    ) -> tuple[dict[int | str, frozenset[str]], dict[int | str, frozenset[int]]]:
        """Multi-cycle dependency tracking (MC-D1).

        Fixed-point iteration propagating deps through DFF D→Q connections.
        Monotonic: deps only grow (union), guaranteed to converge.

        When mc_max_depth=0: single-cycle equivalent (DFF Qs labeled "dff").
        When mc_max_depth=None: unbounded iteration (safety limit 1000).
        When mc_max_depth=N: at most N DFF-propagation iterations.
        """
        deps: dict[int | str, frozenset[str]] = {}
        r_deps: dict[int | str, frozenset[int]] = {}

        # Constants
        deps["0"] = deps["1"] = deps["x"] = frozenset()
        _empty_r: frozenset[int] = frozenset()
        r_deps["0"] = r_deps["1"] = r_deps["x"] = _empty_r

        # Primary inputs
        for net_id in self._s0_nets:
            deps[net_id] = frozenset({"s0"})
            r_deps[net_id] = _empty_r
        for net_id in self._s1_nets:
            deps[net_id] = frozenset({"s1"})
            r_deps[net_id] = _empty_r
        for i, net_id in enumerate(self._r_nets):
            deps[net_id] = frozenset({"r"})
            r_deps[net_id] = frozenset({i})
        for net_id in self._s_nets:
            deps[net_id] = frozenset({"s"})
            r_deps[net_id] = _empty_r
        for net_id in self._p_nets:
            deps.setdefault(net_id, frozenset({"p"}))
            r_deps.setdefault(net_id, _empty_r)

        max_depth = self._mc_max_depth

        # depth=0: single-cycle equivalent (DFF Qs = {"dff"})
        if max_depth is not None and max_depth == 0:
            for _name, _d_net, q_net in self._dff_pairs:
                deps[q_net] = frozenset({"dff"})
                r_deps[q_net] = _empty_r
            self._propagate_deps(deps, r_deps)
            return deps, r_deps

        # DFF Qs start empty (unknown — filled by iteration)
        for _name, _d_net, q_net in self._dff_pairs:
            deps[q_net] = frozenset()
            r_deps[q_net] = _empty_r

        # Initial combinational pass
        self._propagate_deps(deps, r_deps)

        # Fixed-point: DFF D→Q propagation + comb re-propagation
        # Jacobi (snapshot) style: read all D deps first, then write all Q deps.
        # This makes each iteration = exactly one cycle boundary, regardless
        # of _dff_pairs order. (Grok MC-1 audit SIGNIFICANT-1 fix.)
        _MC_D1_SAFETY_LIMIT = 1000
        iteration_limit = _MC_D1_SAFETY_LIMIT if max_depth is None else max_depth
        converged = False
        iterations_done = 0
        for _iteration in range(iteration_limit):
            # Snapshot: collect all D→Q updates before applying any
            updates: list[tuple[int, frozenset[str], frozenset[int]]] = []
            for _name, d_net, q_net in self._dff_pairs:
                new_deps = deps.get(d_net, frozenset())
                new_r = r_deps.get(d_net, frozenset())
                if deps[q_net] != new_deps or r_deps[q_net] != new_r:
                    updates.append((q_net, new_deps, new_r))
            if not updates:
                converged = True
                break
            # Apply all updates atomically
            for q_net, new_d, new_r in updates:
                deps[q_net] = new_d
                r_deps[q_net] = new_r
            self._propagate_deps(deps, r_deps)
            iterations_done += 1

        if not converged:
            # Loop exhausted range — check if last iteration achieved
            # convergence (off-by-one: range(N) gives N apply steps but
            # the N+1th convergence check never runs inside the loop).
            converged = all(
                deps[q_net] == deps.get(d_net, frozenset())
                and r_deps[q_net] == r_deps.get(d_net, frozenset())
                for _name, d_net, q_net in self._dff_pairs
            )

        if not converged and max_depth is None:
            # Unbounded mode hit safety limit — soundness risk.
            # Partial deps could produce false SECURE verdicts.
            # (Grok MC-1 re-audit CRITICAL-1 fix.)
            raise RuntimeError(
                f"MC-D1 did not converge within safety limit "
                f"({_MC_D1_SAFETY_LIMIT} iterations). Module has pipeline "
                f"depth > {_MC_D1_SAFETY_LIMIT}. Use mc_max_depth=N to set "
                f"an explicit bound, or report this as a bug."
            )

        self._mc_iterations = iterations_done

        return deps, r_deps

    def has_share_dependency(self, net_id: int) -> bool:
        """Check if a net's fan-in cone includes any share inputs.

        Uses pre-computed fan-in deps (O(1) lookup, no Z3).
        """
        dep = self._input_deps.get(net_id, frozenset())
        if self.mode == "masked":
            return bool(dep & {"s0", "s1"})
        else:
            return "s" in dep

    def r_bits_in_fanin(self, net_id: int) -> frozenset[int]:
        """Which randomness bit indices are in this net's fan-in cone.

        Returns frozenset of integer indices into self._r_nets.
        Empty frozenset if no randomness bits in fan-in.
        Used by FreshMaskingChecker (RD-01).
        """
        return self._r_input_deps.get(net_id, frozenset())

    def get_r_bit_var_by_index(self, r_idx: int) -> Any:
        """Get the Z3 variable for randomness bit at index r_idx.

        Args:
            r_idx: Index into self._r_nets list.

        Returns:
            z3.BitVec("r_{r_idx}", 1)
        """
        net_id = self._r_nets[r_idx]
        return self._r_bit_vars[net_id]

    def get_dff_output_nets(self) -> list[int]:
        """Net IDs of DFF Q outputs (register cut points)."""
        return [q_net for _name, q_net in self._dff_q_nets]

    def get_primary_input_nets(self) -> list[int]:
        """Net IDs of primary input ports."""
        nets: list[int] = []
        for port in self._ports.values():
            if port["direction"] == "input":
                for net_id in port["bits"]:
                    if isinstance(net_id, int):
                        nets.append(net_id)
        return nets

    # ─── Validation ──────────────────────────────────────────────────

    def _validate_cells(self):
        """Reject netlists with unsupported cell types (M0 §2.2)."""
        bad = {
            n: c["type"]
            for n, c in self._cells.items()
            if c["type"] not in ALLOWED_CELLS
        }
        if bad:
            types = sorted(set(bad.values()))
            cells = list(bad.keys())[:5]
            raise EncodingError(
                f"Unsupported cell types (black-box detected, M0 §2.2): "
                f"{types}. Cells: {cells}"
                f"{'...' if len(bad) > 5 else ''}"
            )

    def _validate_labeling(self):
        """Ensure all input port bits are classified with no overlaps (M0 §2.4).

        Checks:
          1. Every input port bit is classified in exactly one group.
          2. No bit appears in multiple groups (Grok M4 audit Q15).
        """
        input_nets = set()
        for port_name, port in self._ports.items():
            if port["direction"] == "input":
                for net_id in port["bits"]:
                    if isinstance(net_id, int):
                        input_nets.add(net_id)

        # Check for overlapping group assignments (Grok M4 Q15)
        groups = [
            ("s0_bits", self._s0_nets),
            ("s1_bits", self._s1_nets),
            ("r_bits", self._r_nets),
            ("p_bits", self._p_nets),
            ("s_bits", self._s_nets),
        ]
        seen: dict[int, str] = {}
        for group_name, nets in groups:
            for net_id in nets:
                if net_id in seen:
                    raise EncodingError(
                        f"Input bit net {net_id} classified in both "
                        f"'{seen[net_id]}' and '{group_name}' — "
                        f"each input bit must belong to exactly one group"
                    )
                seen[net_id] = group_name

        classified = set(
            self._s0_nets
            + self._s1_nets
            + self._r_nets
            + self._p_nets
            + self._s_nets
        )

        unclassified = input_nets - classified
        if unclassified:
            names = []
            for port_name, port in self._ports.items():
                if port["direction"] == "input":
                    for i, net_id in enumerate(port["bits"]):
                        if net_id in unclassified:
                            if len(port["bits"]) > 1:
                                names.append(f"{port_name}[{i}]")
                            else:
                                names.append(port_name)
            raise EncodingError(
                f"Unclassified input bits (M0 §2.4): {names}"
            )

    # ─── Labeling Resolution ─────────────────────────────────────────

    def _resolve_bits(self, group_spec: dict[str, Any]) -> list[int]:
        """Convert labeling spec → ordered list of net IDs.

        Supports:
            {"port": [0, 1, 2]}     — explicit bit indices
            {"port": "0:11"}        — slice syntax (inclusive)
            {"port": [0]}           — single bit
        """
        nets = []
        for port_name, bit_spec in group_spec.items():
            if port_name not in self._ports:
                raise EncodingError(
                    f"Port '{port_name}' not found in module "
                    f"'{self._module_name}'"
                )
            port_bits = self._ports[port_name]["bits"]

            if isinstance(bit_spec, str) and ":" in bit_spec:
                start, end = map(int, bit_spec.split(":"))
                indices = list(range(start, end + 1))
            elif isinstance(bit_spec, list):
                indices = bit_spec
            elif isinstance(bit_spec, int):
                indices = [bit_spec]
            else:
                raise EncodingError(
                    f"Invalid bit spec for port '{port_name}': {bit_spec}"
                )

            for idx in indices:
                if idx >= len(port_bits):
                    raise EncodingError(
                        f"Bit index {idx} out of range for port "
                        f"'{port_name}' (width={len(port_bits)})"
                    )
                net_id = port_bits[idx]
                if not isinstance(net_id, int):
                    raise EncodingError(
                        f"Port '{port_name}' bit {idx} is constant "
                        f"'{net_id}', not a net"
                    )
                nets.append(net_id)
        return nets

    # ─── Topological Sort ────────────────────────────────────────────

    def _topological_sort(self) -> list[str]:
        """Kahn's algorithm on combinational cells.

        DFF cells are excluded (their Q outputs are sources).
        Raises EncodingError if a combinational cycle is detected.
        """
        comb_cells = {
            n: c for n, c in self._cells.items() if c["type"] not in _DFF_CELLS
        }
        if not comb_cells:
            return []

        # deps[cell] = set of cells that produce its inputs
        deps: dict[str, set[str]] = {name: set() for name in comb_cells}
        reverse_deps: dict[str, set[str]] = {
            name: set() for name in comb_cells
        }

        for name, cell in comb_cells.items():
            for pin, net_ids in cell["connections"].items():
                if pin == "Y":
                    continue
                for net_id in net_ids:
                    if (
                        isinstance(net_id, int)
                        and net_id in self._net_producer
                    ):
                        producer = self._net_producer[net_id]
                        if producer != name:
                            deps[name].add(producer)
                            reverse_deps[producer].add(name)

        in_degree = {name: len(d) for name, d in deps.items()}
        # Deterministic seed: sort by cell name (MC-FM Scope v0.5 topo fix)
        queue = deque(
            sorted(name for name, deg in in_degree.items() if deg == 0)
        )
        order: list[str] = []

        while queue:
            node = queue.popleft()
            order.append(node)
            # Collect newly-zero cells, sort, then extend (deterministic)
            newly_zero = []
            for dependent in reverse_deps[node]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    newly_zero.append(dependent)
            queue.extend(sorted(newly_zero))

        if len(order) != len(comb_cells):
            unordered = set(comb_cells) - set(order)
            raise EncodingError(
                f"Combinational cycle detected: {len(unordered)} cells "
                f"in cycle. First few: {list(unordered)[:5]}"
            )
        return order

    # ─── Wire Name Mapping ───────────────────────────────────────────

    def _build_wire_name_map(self) -> dict[int, str]:
        """Map net IDs → human-readable names from Yosys netnames."""
        name_map: dict[int, str] = {}
        for name, info in self._netnames.items():
            bits = info["bits"]
            hide = info.get("hide_name", 0)
            for i, net_id in enumerate(bits):
                if not isinstance(net_id, int):
                    continue
                wire_name = f"{name}[{i}]" if len(bits) > 1 else name
                # Prefer non-hidden names
                if net_id not in name_map or not hide:
                    name_map[net_id] = wire_name
        return name_map

    def wire_name(self, net_id: int) -> str:
        """Human-readable name for a net ID."""
        if net_id in self._wire_names:
            return self._wire_names[net_id]
        # Fall back to producing cell name (MINOR fix, Grok M4a audit)
        if net_id in self._net_producer:
            return f"{self._net_producer[net_id]}_Y"
        return f"net_{net_id}"

    # ─── Z3 Expression Building ──────────────────────────────────────

    def _propagate_comb_expressions(
        self, expr: dict[int | str, Any]
    ) -> tuple[dict[int | str, Any], int]:
        """Propagate Z3 expressions through combinational cells in topo order.

        SINGLE source of truth for gate dispatch. Both _build_expressions()
        and _build_expressions_mc() call this. See MC-FM Scope v0.5 §2.6.1.

        Args:
            expr: dict mapping net_id -> Z3 expression. Must include all
                  primary inputs and DFF Q outputs before calling.

        Returns:
            Tuple of (updated expr dict, count of None outputs from unknown cells).
        """
        z3 = self._ensure_z3()
        unknown_count = 0
        unknown_types: set[str] = set()

        for cell_name in self._topo_order:
            cell = self._cells[cell_name]
            ctype = cell["type"]
            conn = cell["connections"]
            y_net = conn["Y"][0]

            if ctype == "$_NOT_":
                a = expr.get(conn["A"][0])
                expr[y_net] = ~a if a is not None else None
            elif ctype in ("$_AND_", "$_NAND_"):
                a = expr.get(conn["A"][0])
                b = expr.get(conn["B"][0])
                if a is not None and b is not None:
                    result = a & b
                    expr[y_net] = ~result if "NAND" in ctype else result
                else:
                    expr[y_net] = None
            elif ctype in ("$_OR_", "$_NOR_"):
                a = expr.get(conn["A"][0])
                b = expr.get(conn["B"][0])
                if a is not None and b is not None:
                    result = a | b
                    expr[y_net] = ~result if "NOR" in ctype else result
                else:
                    expr[y_net] = None
            elif ctype in ("$_XOR_", "$_XNOR_"):
                a = expr.get(conn["A"][0])
                b = expr.get(conn["B"][0])
                if a is not None and b is not None:
                    result = a ^ b
                    expr[y_net] = ~result if "XNOR" in ctype else result
                else:
                    expr[y_net] = None
            elif ctype == "$_MUX_":
                a = expr.get(conn["A"][0])
                b = expr.get(conn["B"][0])
                s = expr.get(conn["S"][0])
                if all(x is not None for x in (a, b, s)):
                    expr[y_net] = z3.If(s == z3.BitVecVal(1, 1), b, a)
                else:
                    expr[y_net] = None
            elif ctype == "$_ANDNOT_":
                a = expr.get(conn["A"][0])
                b = expr.get(conn["B"][0])
                if a is not None and b is not None:
                    expr[y_net] = a & ~b
                else:
                    expr[y_net] = None
            elif ctype == "$_ORNOT_":
                a = expr.get(conn["A"][0])
                b = expr.get(conn["B"][0])
                if a is not None and b is not None:
                    expr[y_net] = a | ~b
                else:
                    expr[y_net] = None
            elif ctype in ("$_AOI3_", "$_OAI3_"):
                a = expr.get(conn["A"][0])
                b = expr.get(conn["B"][0])
                c = expr.get(conn["C"][0])
                if all(x is not None for x in (a, b, c)):
                    if "AOI" in ctype:
                        expr[y_net] = ~((a & b) | c)
                    else:
                        expr[y_net] = ~((a | b) & c)
                else:
                    expr[y_net] = None
            elif ctype in ("$_AOI4_", "$_OAI4_"):
                a = expr.get(conn["A"][0])
                b = expr.get(conn["B"][0])
                c = expr.get(conn["C"][0])
                d = expr.get(conn["D"][0])
                if all(x is not None for x in (a, b, c, d)):
                    if "AOI" in ctype:
                        expr[y_net] = ~((a & b) | (c & d))
                    else:
                        expr[y_net] = ~((a | b) & (c | d))
                else:
                    expr[y_net] = None
            else:
                unknown_count += 1
                unknown_types.add(ctype)
                expr[y_net] = None

        if unknown_count > 0:
            logger.warning(
                "Unknown cell types: %s (%d cells, %.1f%%)",
                sorted(unknown_types),
                unknown_count,
                100 * unknown_count / max(1, len(self._topo_order)),
            )

        return expr, unknown_count

    def _ensure_z3(self):
        if self._z3 is None:
            try:
                import z3

                self._z3 = z3
            except ImportError as e:
                raise EncodingError(
                    "Z3 not found. Install with: pip install z3-solver"
                ) from e
        return self._z3

    def _build_expressions(self, s0, s1, r, p) -> dict[int | str, Any]:
        """Build Z3 expressions for all nets given input variables.

        For masked: s0, s1 are BitVecs; r, p may be None (if width=0).
        For unmasked: s0=secret, s1=None, r=None, p may be None.

        DFF Q outputs get fresh free BitVec variables with fixed names,
        so they are shared across repeated calls (correct for dependency
        queries where register state must be identical).
        """
        z3 = self._ensure_z3()
        expr: dict[int | str, Any] = {}

        # Constants (Yosys uses "0"/"1"/"x" strings in connections)
        expr["0"] = z3.BitVecVal(0, 1)
        expr["1"] = z3.BitVecVal(1, 1)
        expr["x"] = z3.BitVec("__x_dc", 1)  # don't-care → free (Grok M4 Q9)

        # Assign primary input groups
        def assign_group(nets: list[int], var):
            for i, net_id in enumerate(nets):
                if len(nets) == 1:
                    expr[net_id] = var
                else:
                    expr[net_id] = z3.Extract(i, i, var)

        if self.mode == "masked":
            if self._s0_nets and s0 is not None:
                assign_group(self._s0_nets, s0)
            if self._s1_nets and s1 is not None:
                assign_group(self._s1_nets, s1)
            # r allocation: two modes (Grok RD-01 FATAL fix).
            # - D1 mode (r is not None): use group vector via assign_group
            #   (Extract(i, i, r)) — preserves original D1 expression trees.
            # - FM mode (r is None): use pre-allocated per-bit BitVec("r_i", 1)
            #   for z3.substitute() in FreshMaskingChecker (Grok v0.1 AV6+AV9).
            if self._r_nets:
                if r is not None:
                    assign_group(self._r_nets, r)
                else:
                    for net_id in self._r_nets:
                        expr[net_id] = self._r_bit_vars[net_id]
            if self._p_nets and p is not None:
                assign_group(self._p_nets, p)
        else:
            if self._s_nets and s0 is not None:
                assign_group(self._s_nets, s0)
            if self._p_nets and p is not None:
                assign_group(self._p_nets, p)

        # DFF Q outputs = pre-allocated free variables (combinational cut points)
        for q_net, dff_var in self._dff_vars.items():
            expr[q_net] = dff_var

        # Shared gate dispatch (single source of truth for all cell types)
        expr, unknown_count = self._propagate_comb_expressions(expr)
        if unknown_count > 0:
            logger.warning(
                "_build_expressions: %d unknown cell outputs", unknown_count
            )

        return expr

    def _build_expressions_mc(self, s0, s1, r, p) -> dict[int | str, Any]:
        """Build Z3 expressions with multi-cycle DFF propagation for MC-FM.

        Layered expression building: starts with single-cycle expressions,
        then iteratively substitutes DFF Q free vars with their D expressions
        until convergence or layer limit.

        Uses per-bit r_i variables (not group vector) for FM bijection queries.
        The `r` parameter is ignored; per-bit vars from self._r_bit_vars are used.

        Handles cycles via iterative Tarjan SCC detection (cycle DFFs kept as
        free vars). Handles expression blowup via per-DFF size guards.

        See MC-FM Scope v0.5 Appendix A (authoritative algorithm).
        """
        z3 = self._ensure_z3()
        expr: dict[int | str, Any] = {}

        # Constants — MC-FM uses constant 0 for don't-care (consistent
        # with MC-D1's deps["x"] = frozenset()). D1 mode uses free var
        # (Grok M4 Q9 fix) — these are different contexts.
        expr["0"] = z3.BitVecVal(0, 1)
        expr["1"] = z3.BitVecVal(1, 1)
        expr["x"] = z3.BitVecVal(0, 1)

        # Primary inputs: per-bit variables for FM bijection queries
        for i, net_id in enumerate(self._s0_nets):
            expr[net_id] = z3.Extract(i, i, s0) if len(self._s0_nets) > 1 else s0
        for i, net_id in enumerate(self._s1_nets):
            expr[net_id] = z3.Extract(i, i, s1) if len(self._s1_nets) > 1 else s1
        # r: per-bit vars (not group vector) for FM substitute
        for net_id in self._r_nets:
            expr[net_id] = self._r_bit_vars[net_id]
        if p is not None:
            for i, net_id in enumerate(self._p_nets):
                expr[net_id] = z3.Extract(i, i, p) if len(self._p_nets) > 1 else p

        # DFF Q outputs: fresh free variables (Layer 0 boundary)
        for name, d_net, q_net in self._dff_pairs:
            expr[q_net] = self._dff_vars[q_net]

        # Layer 0: combinational propagation
        expr, unknown_count = self._propagate_comb_expressions(expr)
        if unknown_count > len(self._topo_order) * 0.01:
            raise RuntimeError(
                f"MC-FM aborted: {unknown_count}/{len(self._topo_order)} cells "
                f"({100 * unknown_count / max(1, len(self._topo_order)):.1f}%) "
                f"have unknown types. Module is FM-blind."
            )

        # Identify propagate_dffs: DFFs whose MC-D1 deps differ from
        # single-cycle deps (frozenset({"dff"})). When multi_cycle=True,
        # self._input_deps is the MC result.
        propagate_dffs = []
        for name, d_net, q_net in self._dff_pairs:
            if self._input_deps.get(q_net, frozenset()) != frozenset({"dff"}):
                propagate_dffs.append((name, d_net, q_net))

        if not propagate_dffs:
            return expr  # Nothing to propagate (single-cycle equivalent)

        # Skip-large guard
        if len(propagate_dffs) > self._mc_fm_max_propagate:
            logger.warning(
                "MC-FM: %d propagate_dffs exceeds limit %d. "
                "Skipping MC-FM (D1 results only).",
                len(propagate_dffs),
                self._mc_fm_max_propagate,
            )
            return expr

        # Single-pass adjacency: O(n * |expr|) via _collect_free_vars
        var_id_to_dff: dict[int, str] = {}
        for name, _, q_net in propagate_dffs:
            var_id_to_dff[self._dff_vars[q_net].get_id()] = name

        dff_adj: dict[str, set[str]] = {
            name: set() for name, _, _ in propagate_dffs
        }
        for name, d_net, q_net in propagate_dffs:
            d_expr = expr.get(d_net)
            if d_expr is None:
                continue
            for fv in _collect_free_vars(d_expr):
                dep_name = var_id_to_dff.get(fv.get_id())
                if dep_name is not None:
                    dff_adj[name].add(dep_name)

        # Tarjan SCC — iterative, handles self-loops + multi-DFF cycles
        sccs = _tarjan_scc(dff_adj)
        cycle_dffs: set[str] = set()
        for scc in sccs:
            if len(scc) > 1:
                cycle_dffs |= scc
            elif len(scc) == 1:
                name = next(iter(scc))
                if name in dff_adj.get(name, set()):
                    cycle_dffs.add(name)

        if cycle_dffs:
            logger.info(
                "MC-FM: %d DFFs in cycles, kept as free vars: %s%s",
                len(cycle_dffs),
                sorted(list(cycle_dffs))[:10],
                "..." if len(cycle_dffs) > 10 else "",
            )

        propagate_dffs = [
            (n, d, q) for n, d, q in propagate_dffs if n not in cycle_dffs
        ]

        if not propagate_dffs:
            return expr  # All propagate_dffs were in cycles

        # Post-SCC safety assertion
        for name, d_net, q_net in propagate_dffs:
            d_expr = expr.get(d_net)
            if d_expr is not None:
                own_var = self._dff_vars[q_net]
                if _expr_contains_var(d_expr, own_var):
                    raise RuntimeError(
                        f"BUG: DFF {name} has self-referential D expression "
                        f"after SCC removal. Tarjan SCC failed to detect cycle."
                    )

        # Layered propagation with guards
        layer_limit = min(
            len(propagate_dffs) + 1, self._mc_fm_max_layers
        )
        frozen_dffs: set[str] = set()

        for layer in range(layer_limit):
            changed = False
            for name, d_net, q_net in propagate_dffs:
                if name in frozen_dffs:
                    continue
                d_expr = expr[d_net]
                if not _exprs_equal(expr[q_net], d_expr):
                    expr[q_net] = d_expr
                    changed = True

            if not changed:
                break

            expr, _ = self._propagate_comb_expressions(expr)

            # Per-DFF expression size guard
            for name, d_net, q_net in propagate_dffs:
                if name in frozen_dffs:
                    continue
                d_expr = expr.get(d_net)
                if d_expr is not None:
                    count = _expr_node_count(d_expr)
                    if count > self._mc_fm_max_expr_nodes:
                        logger.warning(
                            "MC-FM: DFF %s has %d expr nodes "
                            "(limit %d). Freezing at layer %d.",
                            name,
                            count,
                            self._mc_fm_max_expr_nodes,
                            layer,
                        )
                        frozen_dffs.add(name)

        if layer == layer_limit - 1 and changed:
            logger.warning(
                "MC-FM: did not converge in %d layers. "
                "Partial expressions used (sound — FP not FN).",
                layer_limit,
            )

        return expr

    # ─── Wire Function Builders ──────────────────────────────────────

    def build_wire_fn(self, net_id: int) -> Callable:
        """Build a wire_fn callable for ProbingVerifier.

        Returns:
            Masked:   wire_fn(s0, s1, r, p) → Z3 BitVec(1)
            Unmasked: wire_fn(s, p) → Z3 BitVec(1)
        """
        if self.mode == "masked":

            def wire_fn(s0, s1, r, p):
                return self._build_expressions(s0, s1, r, p)[net_id]

            return wire_fn
        else:

            def wire_fn(s, p):
                return self._build_expressions(s, None, None, p)[net_id]

            return wire_fn

    def get_combinational_output_nets(self) -> list[int]:
        """Net IDs produced by combinational cells."""
        return sorted(self._net_producer.keys())

    def get_all_net_ids(self) -> list[int]:
        """All net IDs in the netlist (inputs + internal + outputs)."""
        nets: set[int] = set()
        for port in self._ports.values():
            for net_id in port["bits"]:
                if isinstance(net_id, int):
                    nets.add(net_id)
        for cell in self._cells.values():
            for pin_nets in cell["connections"].values():
                for net_id in pin_nets:
                    if isinstance(net_id, int):
                        nets.add(net_id)
        return sorted(nets)


# =============================================================================
# Parallel Worker Function (top-level for pickle compatibility)
# =============================================================================


def _verify_wire_batch(args: tuple) -> list[tuple[str, str, dict]]:
    """Worker for parallel wire verification. Runs in a subprocess.

    Each worker rebuilds its own NetlistAdapter + Z3 context (Z3 objects
    are not serializable). This adds ~1-2s setup per worker for small
    netlists, trivial compared to the hours saved on large SAT solving.

    Args:
        args: Tuple of (netlist_path, labeling, module_name,
              wire_assignments, timeout_ms) where wire_assignments is
              a list of (net_id, wire_name) pairs.

    Returns:
        List of (wire_name, verdict_str, result_dict) tuples.
    """
    netlist_path, labeling, module_name, wire_assignments, timeout_ms = args

    # Each worker rebuilds its own adapter + Z3 expressions
    adapter = NetlistAdapter(netlist_path, labeling, module_name)
    verifier = ProbingVerifier(timeout_ms=timeout_ms)
    z3 = verifier._ensure_z3()
    mode = adapter.mode

    # Build expression maps (same logic as verify_circuit)
    # Grok RD-01 FATAL fix: pass group-r vector to preserve D1 expression
    # trees (per-bit r vars only used for FM mode via r=None).
    if mode == "masked":
        s0_w, s1_w = adapter.s0_width, adapter.s1_width
        r_w = adapter.r_width
        p_w = adapter.p_width

        s0 = z3.BitVec("s0", s0_w)
        s0p = z3.BitVec("s0p", s0_w)
        s1 = z3.BitVec("s1", s1_w)
        s1p = z3.BitVec("s1p", s1_w)
        r = z3.BitVec("r", r_w) if r_w > 0 else None
        p = z3.BitVec("p", p_w) if p_w > 0 else None

        expr_base = adapter._build_expressions(s0, s1, r, p)
        expr_s0v = adapter._build_expressions(s0p, s1, r, p)
        expr_s1v = adapter._build_expressions(s0, s1p, r, p)
    else:
        s_w = adapter.s_width
        p_w = adapter.p_width

        s = z3.BitVec("s", s_w)
        sp = z3.BitVec("sp", s_w)
        p = z3.BitVec("p", p_w) if p_w > 0 else None

        expr_base = adapter._build_expressions(s, None, None, p)
        expr_sv = adapter._build_expressions(sp, None, None, p)

    batch_results: list[tuple[str, str, dict]] = []

    for net_id, wire_name in wire_assignments:
        wire_start = time.monotonic()

        if mode == "masked":
            w_base = expr_base[net_id]
            w_s0v = expr_s0v[net_id]
            w_s1v = expr_s1v[net_id]

            d0 = verifier._run_dependency_query(
                [s0 != s0p, w_base != w_s0v], "D0"
            )
            d1 = verifier._run_dependency_query(
                [s1 != s1p, w_base != w_s1v], "D1"
            )

            wire_elapsed = time.monotonic() - wire_start

            if d0.satisfiable is None or d1.satisfiable is None:
                verdict = SecurityVerdict.UNKNOWN
            elif d0.satisfiable and d1.satisfiable:
                verdict = SecurityVerdict.POTENTIALLY_INSECURE
            else:
                verdict = SecurityVerdict.SECURE

            result = WireSecurityResult(
                wire_name=wire_name,
                verdict=verdict,
                depends_on_s0=d0.satisfiable,
                depends_on_s1=d1.satisfiable,
                dependency_results=[d0, d1],
                time_seconds=wire_elapsed,
            )
        else:
            w_base = expr_base[net_id]
            w_sv = expr_sv[net_id]

            ds = verifier._run_dependency_query(
                [s != sp, w_base != w_sv], "Ds"
            )

            wire_elapsed = time.monotonic() - wire_start

            if ds.satisfiable is None:
                verdict = SecurityVerdict.UNKNOWN
            elif ds.satisfiable:
                verdict = SecurityVerdict.POTENTIALLY_INSECURE
            else:
                verdict = SecurityVerdict.SECURE

            result = WireSecurityResult(
                wire_name=wire_name,
                verdict=verdict,
                depends_on_secret=ds.satisfiable,
                dependency_results=[ds],
                time_seconds=wire_elapsed,
            )

        batch_results.append(
            (wire_name, verdict.value, result)
        )

    return batch_results


# =============================================================================
# M4b — Whole-Circuit Verifier
# =============================================================================


@dataclass
class CircuitReport:
    """Aggregated verification results for an entire circuit.

    Results are keyed by unique wire identifier (net_id-based to avoid
    name collisions — Grok M4b audit Q2/Q5/Q7 fix).

    Attributes:
        module_name: Yosys module name.
        mode: "masked" or "unmasked".
        total_wires: Number of wires in scope (verified + constant-skipped).
        secure_count: Wires with SECURE verdict.
        insecure_count: Wires with POTENTIALLY_INSECURE verdict.
        unknown_count: Wires with UNKNOWN verdict (timeout).
        constant_count: Wires skipped as constant (no share variables).
        results: Per-wire results, keyed by unique wire identifier.
        total_time_seconds: Wall-clock time for all queries.
        cell_count: Total cells in netlist.
        combinational_cell_count: Combinational cells only.
        dff_count: Register count.
    """

    module_name: str
    mode: str
    total_wires: int
    secure_count: int
    insecure_count: int
    unknown_count: int
    constant_count: int
    results: dict[str, WireSecurityResult] = field(default_factory=dict)
    total_time_seconds: float = 0.0
    cell_count: int = 0
    combinational_cell_count: int = 0
    dff_count: int = 0

    @property
    def insecure_wires(self) -> list[str]:
        """Names of wires flagged POTENTIALLY_INSECURE."""
        return [
            name
            for name, r in self.results.items()
            if r.verdict == SecurityVerdict.POTENTIALLY_INSECURE
        ]

    @property
    def secure_wires(self) -> list[str]:
        """Names of wires with SECURE verdict."""
        return [
            name
            for name, r in self.results.items()
            if r.verdict == SecurityVerdict.SECURE
        ]

    def summary(self) -> str:
        """One-line summary string."""
        return (
            f"{self.module_name} ({self.mode}): "
            f"{self.total_wires} wires — "
            f"{self.secure_count} secure, "
            f"{self.insecure_count} insecure, "
            f"{self.unknown_count} unknown, "
            f"{self.constant_count} constant | "
            f"{self.total_time_seconds:.2f}s"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "mode": self.mode,
            "total_wires": self.total_wires,
            "secure_count": self.secure_count,
            "insecure_count": self.insecure_count,
            "unknown_count": self.unknown_count,
            "constant_count": self.constant_count,
            "total_time_seconds": self.total_time_seconds,
            "cell_count": self.cell_count,
            "combinational_cell_count": self.combinational_cell_count,
            "dff_count": self.dff_count,
            "results": {
                name: r.to_dict() for name, r in self.results.items()
            },
        }


# =============================================================================
# RD-01 — Fresh Masking Refinement Types
# =============================================================================


class FMVerdict(Enum):
    """Fresh masking refinement verdict (separate from D1).

    This is a REFINEMENT verdict — it appears in a separate column
    from the D1 verdict. FM can only promote (INSECURE → SECURE),
    never demote. See RD-01 Scope v0.3 §3.3.
    """

    SECURE = "fm_secure"
    INDETERMINATE = "fm_indeterminate"
    NOT_CHECKED = "fm_not_checked"


@dataclass
class FMWireResult:
    """FM result for a single wire."""

    wire_name: str
    d1_verdict: SecurityVerdict
    fm_verdict: FMVerdict
    masking_r_bit: int | None = None  # Which r_i proved bijection (if SECURE)
    fm_time_seconds: float = 0.0


@dataclass
class FMRefinedReport:
    """Two-column report: D1 verdicts (immutable) + FM refinement.

    D1 verdicts are NEVER overwritten. FM results appear in a
    separate column. See RD-01 Scope v0.3 §3.3.
    """

    module_name: str
    d1_report: CircuitReport
    fm_results: dict[str, FMWireResult] = field(default_factory=dict)
    fm_promoted_count: int = 0
    fm_indeterminate_count: int = 0
    fm_not_checked_count: int = 0
    fm_time_seconds: float = 0.0
    fm_timed_out: bool = False

    def summary(self) -> str:
        d1 = self.d1_report
        timeout_str = " [FM TIMEOUT]" if self.fm_timed_out else ""
        return (
            f"{self.module_name}: D1={d1.insecure_count} insecure | "
            f"FM: {self.fm_promoted_count} promoted, "
            f"{self.fm_indeterminate_count} indeterminate"
            f"{timeout_str} | {self.fm_time_seconds:.2f}s"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "d1_report": self.d1_report.to_dict(),
            "fm_promoted_count": self.fm_promoted_count,
            "fm_indeterminate_count": self.fm_indeterminate_count,
            "fm_not_checked_count": self.fm_not_checked_count,
            "fm_time_seconds": self.fm_time_seconds,
            "fm_timed_out": self.fm_timed_out,
        }


class FreshMaskingChecker:
    """RD-01: Single-bit XOR fresh masking detection.

    For each D1-INSECURE wire, checks if any randomness bit r_i
    acts as a bijection (flipping r_i always flips w). If so,
    the wire is provably uniform → FM verdict: SECURE.

    Z3 Query (FM_i):
        ∃ s0, s1, r_other, p : w(r_i=0) = w(r_i=1)
        UNSAT → bijection → SECURE
        SAT   → not bijection → try next r_i

    See RD-01 Scope v0.3 §3-4.
    """

    def __init__(
        self,
        query_timeout_ms: int = 10_000,
        module_timeout_s: float = 1800.0,
    ):
        self._query_timeout_ms = query_timeout_ms
        self._module_timeout_s = module_timeout_s
        self._z3 = None

    def _ensure_z3(self):
        if self._z3 is None:
            try:
                import z3

                self._z3 = z3
            except ImportError as e:
                raise EncodingError(
                    "Z3 not found. Install with: pip install z3-solver"
                ) from e
        return self._z3

    def check_wire(
        self,
        w_expr: Any,
        r_bit_indices: frozenset[int],
        adapter: NetlistAdapter,
        module_start_time: float,
    ) -> tuple[FMVerdict, int | None]:
        """Check if wire expression has a single-bit XOR fresh mask.

        Args:
            w_expr: Z3 expression for the wire.
            r_bit_indices: Which r_i indices are in this wire's fan-in.
            adapter: NetlistAdapter for r bit variable lookup.
            module_start_time: Module-level start time for timeout enforcement
                (Grok RD-01 re-audit fix: required to prevent unbounded runtime).

        Returns:
            (verdict, masking_r_bit) — masking_r_bit is the index if SECURE.
        """
        if not r_bit_indices:
            return FMVerdict.INDETERMINATE, None

        z3 = self._ensure_z3()

        for r_idx in sorted(r_bit_indices):
            # Grok RD-01 SIGNIFICANT fix: check timeout between r_bit queries
            if time.monotonic() - module_start_time > self._module_timeout_s:
                return FMVerdict.INDETERMINATE, None

            r_var = adapter.get_r_bit_var_by_index(r_idx)

            w_0 = z3.substitute(w_expr, (r_var, z3.BitVecVal(0, 1)))
            w_1 = z3.substitute(w_expr, (r_var, z3.BitVecVal(1, 1)))

            solver = z3.Solver()
            solver.set("timeout", self._query_timeout_ms)
            solver.add(w_0 == w_1)

            result = solver.check()
            if result == z3.unsat:
                return FMVerdict.SECURE, r_idx
            # SAT or unknown → try next r_i

        return FMVerdict.INDETERMINATE, None


class CircuitVerifier:
    """Verify all wires in a gate-level netlist.

    M4b deliverable: orchestrates NetlistAdapter + ProbingVerifier to
    verify every probeable wire (combinational outputs + DFF Q outputs).

    Grok M4b audit fixes applied:
        Q2/Q5/Q7: Net-ID-based dedup prevents wire name collisions
        Q3: DFF Q outputs included (CRITICAL fix)
        Q4: Fan-in-based constant check (O(1) per net, no Z3 rebuild)

    Usage:
        cv = CircuitVerifier(timeout_ms=30_000)
        report = cv.verify_circuit(
            "module.json",
            {"mode": "masked", "s0_bits": ..., "s1_bits": ..., ...},
        )
        print(report.summary())
        for name in report.insecure_wires:
            print(f"  INSECURE: {name}")
    """

    def __init__(self, timeout_ms: int = 30_000):
        self._verifier = ProbingVerifier(timeout_ms=timeout_ms)

    def verify_circuit(
        self,
        netlist: str | Path | dict,
        labeling: dict[str, Any],
        module_name: str | None = None,
        skip_constants: bool = True,
        n_workers: int = 1,
        run_fm: bool = False,
        fm_timeout_s: float = 1800.0,
        fm_query_timeout_ms: int = 10_000,
        multi_cycle: bool = False,
        mc_fm_max_propagate: int = 50_000,
        mc_fm_max_expr_nodes: int = 100_000,
        mc_fm_max_layers: int = 50,
    ) -> CircuitReport | FMRefinedReport:
        """Verify all probeable wires in a netlist.

        Verifies combinational output wires + DFF Q outputs (register
        cut points). Primary inputs are excluded (trivially classified
        by labeling, not circuit behavior).

        Args:
            netlist: Yosys JSON dict or path to JSON file.
            labeling: Input grouping config (mode, s0_bits, etc.).
            module_name: Which module to analyze (default: first).
            skip_constants: Skip nets with no share variables in fan-in.
            n_workers: Number of parallel worker processes. When > 1,
                each worker rebuilds its own NetlistAdapter + Z3 context.
                Requires netlist to be a file path (not dict).
            run_fm: If True, run RD-01 fresh masking refinement on
                D1-INSECURE wires (masked mode only).
            fm_timeout_s: Module-level timeout for FM phase (default 1800s).
            fm_query_timeout_ms: Per-query timeout for FM Z3 checks.
            multi_cycle: If True, use MC-D1 dep tracking + MC-FM expressions.
            mc_fm_max_propagate: Max propagate_dffs before skipping MC-FM.
            mc_fm_max_expr_nodes: Per-DFF expression size limit.
            mc_fm_max_layers: Max layered propagation iterations.

        Returns:
            CircuitReport if run_fm=False.
            FMRefinedReport if run_fm=True (contains D1 report + FM results).
        """
        # Resolve netlist path for parallel workers
        netlist_path: str | None = None
        if isinstance(netlist, (str, Path)):
            netlist_path = str(netlist)

        # Fall back to sequential if netlist is a dict (not serializable)
        if n_workers > 1 and netlist_path is None:
            logger.warning(
                "n_workers=%d but netlist is a dict (not a file path). "
                "Falling back to n_workers=1.", n_workers
            )
            n_workers = 1

        adapter = NetlistAdapter(
            netlist, labeling, module_name,
            multi_cycle=multi_cycle,
            mc_fm_max_propagate=mc_fm_max_propagate,
            mc_fm_max_expr_nodes=mc_fm_max_expr_nodes,
            mc_fm_max_layers=mc_fm_max_layers,
        )
        mode = adapter.mode

        # CRITICAL fix (Grok Q3): verify ALL probeable wires —
        # combinational outputs + DFF Q outputs
        comb_nets = adapter.get_combinational_output_nets()
        dff_nets = adapter.get_dff_output_nets()
        all_probe_nets = comb_nets + dff_nets

        # SIGNIFICANT fix (Grok Q2/Q5/Q7): deduplicate wire names
        # by appending net_id on collision
        used_names: set[str] = set()
        work_items: list[tuple[int, str]] = []
        constant = 0

        for net_id in all_probe_nets:
            raw_name = adapter.wire_name(net_id)
            if raw_name in used_names:
                wire_name = f"{raw_name} [net {net_id}]"
            else:
                wire_name = raw_name
            used_names.add(wire_name)

            # SIGNIFICANT fix (Grok Q4): O(1) fan-in check
            if skip_constants and not adapter.has_share_dependency(net_id):
                constant += 1
                continue

            work_items.append((net_id, wire_name))

        start = time.monotonic()

        if n_workers > 1 and len(work_items) > 1:
            results, secure, insecure, unknown = self._verify_parallel(
                netlist_path, labeling, adapter.module_name,
                work_items, n_workers,
            )
        else:
            results, secure, insecure, unknown = self._verify_sequential(
                adapter, work_items,
            )

        elapsed = time.monotonic() - start

        d1_report = CircuitReport(
            module_name=adapter.module_name,
            mode=mode,
            total_wires=secure + insecure + unknown + constant,
            secure_count=secure,
            insecure_count=insecure,
            unknown_count=unknown,
            constant_count=constant,
            results=results,
            total_time_seconds=elapsed,
            cell_count=adapter.cell_count,
            combinational_cell_count=adapter.combinational_cell_count,
            dff_count=adapter.dff_count,
        )

        if not run_fm:
            return d1_report

        # RD-01: Fresh masking refinement pass
        if mode != "masked" or insecure == 0:
            return FMRefinedReport(
                module_name=adapter.module_name,
                d1_report=d1_report,
                fm_not_checked_count=secure + unknown + constant,
            )

        return self._run_fm_pass(
            adapter, d1_report, work_items,
            fm_timeout_s, fm_query_timeout_ms,
        )

    def _verify_sequential(
        self,
        adapter: NetlistAdapter,
        work_items: list[tuple[int, str]],
    ) -> tuple[dict[str, WireSecurityResult], int, int, int]:
        """Verify wires sequentially (original path)."""
        mode = adapter.mode
        z3 = self._verifier._ensure_z3()

        # SIGNIFICANT fix (Grok M4 Q13): batch expression building.
        # Grok RD-01 FATAL fix: pass group-r vector to preserve D1 expression
        # trees (per-bit r vars only used for FM mode via r=None).
        if mode == "masked":
            s0_w, s1_w = adapter.s0_width, adapter.s1_width
            r_w = adapter.r_width
            p_w = adapter.p_width

            s0 = z3.BitVec("s0", s0_w)
            s0p = z3.BitVec("s0p", s0_w)
            s1 = z3.BitVec("s1", s1_w)
            s1p = z3.BitVec("s1p", s1_w)
            r = z3.BitVec("r", r_w) if r_w > 0 else None
            p = z3.BitVec("p", p_w) if p_w > 0 else None

            expr_base = adapter._build_expressions(s0, s1, r, p)
            expr_s0v = adapter._build_expressions(s0p, s1, r, p)
            expr_s1v = adapter._build_expressions(s0, s1p, r, p)
        else:
            s_w = adapter.s_width
            p_w = adapter.p_width

            s = z3.BitVec("s", s_w)
            sp = z3.BitVec("sp", s_w)
            p = z3.BitVec("p", p_w) if p_w > 0 else None

            expr_base = adapter._build_expressions(s, None, None, p)
            expr_sv = adapter._build_expressions(sp, None, None, p)

        results: dict[str, WireSecurityResult] = {}
        secure = insecure = unknown = 0

        for net_id, wire_name in work_items:
            wire_start = time.monotonic()

            if mode == "masked":
                w_base = expr_base[net_id]
                w_s0v = expr_s0v[net_id]
                w_s1v = expr_s1v[net_id]

                d0 = self._verifier._run_dependency_query(
                    [s0 != s0p, w_base != w_s0v], "D0"
                )
                d1 = self._verifier._run_dependency_query(
                    [s1 != s1p, w_base != w_s1v], "D1"
                )

                wire_elapsed = time.monotonic() - wire_start

                if d0.satisfiable is None or d1.satisfiable is None:
                    verdict = SecurityVerdict.UNKNOWN
                elif d0.satisfiable and d1.satisfiable:
                    verdict = SecurityVerdict.POTENTIALLY_INSECURE
                else:
                    verdict = SecurityVerdict.SECURE

                result = WireSecurityResult(
                    wire_name=wire_name,
                    verdict=verdict,
                    depends_on_s0=d0.satisfiable,
                    depends_on_s1=d1.satisfiable,
                    dependency_results=[d0, d1],
                    time_seconds=wire_elapsed,
                )
            else:
                w_base = expr_base[net_id]
                w_sv = expr_sv[net_id]

                ds = self._verifier._run_dependency_query(
                    [s != sp, w_base != w_sv], "Ds"
                )

                wire_elapsed = time.monotonic() - wire_start

                if ds.satisfiable is None:
                    verdict = SecurityVerdict.UNKNOWN
                elif ds.satisfiable:
                    verdict = SecurityVerdict.POTENTIALLY_INSECURE
                else:
                    verdict = SecurityVerdict.SECURE

                result = WireSecurityResult(
                    wire_name=wire_name,
                    verdict=verdict,
                    depends_on_secret=ds.satisfiable,
                    dependency_results=[ds],
                    time_seconds=wire_elapsed,
                )

            results[wire_name] = result

            if result.verdict == SecurityVerdict.SECURE:
                secure += 1
            elif result.verdict == SecurityVerdict.POTENTIALLY_INSECURE:
                insecure += 1
            else:
                unknown += 1

        return results, secure, insecure, unknown

    def _verify_parallel(
        self,
        netlist_path: str,
        labeling: dict[str, Any],
        module_name: str,
        work_items: list[tuple[int, str]],
        n_workers: int,
    ) -> tuple[dict[str, WireSecurityResult], int, int, int]:
        """Verify wires in parallel using multiprocessing.Pool.

        Partitions work_items into n_workers contiguous chunks.
        Each worker rebuilds its own NetlistAdapter + Z3 context.
        """
        # Partition into contiguous chunks
        chunk_size = max(1, len(work_items) // n_workers)
        chunks: list[list[tuple[int, str]]] = []
        for i in range(0, len(work_items), chunk_size):
            chunks.append(work_items[i : i + chunk_size])

        # Merge small trailing chunk into the last full chunk
        if len(chunks) > n_workers and len(chunks[-1]) < chunk_size:
            chunks[-2].extend(chunks[-1])
            chunks.pop()

        pool_args = [
            (netlist_path, labeling, module_name, chunk,
             self._verifier.timeout_ms)
            for chunk in chunks
        ]

        logger.info(
            "Parallel verification: %d wires across %d workers "
            "(chunks: %s)",
            len(work_items), len(pool_args),
            [len(c) for c in chunks],
        )

        results: dict[str, WireSecurityResult] = {}
        secure = insecure = unknown = 0

        with multiprocessing.Pool(processes=len(pool_args)) as pool:
            batch_results_list = pool.map(_verify_wire_batch, pool_args)

        for batch_results in batch_results_list:
            for wire_name, verdict_str, result in batch_results:
                results[wire_name] = result
                if result.verdict == SecurityVerdict.SECURE:
                    secure += 1
                elif result.verdict == SecurityVerdict.POTENTIALLY_INSECURE:
                    insecure += 1
                else:
                    unknown += 1

        return results, secure, insecure, unknown

    def _run_fm_pass(
        self,
        adapter: NetlistAdapter,
        d1_report: CircuitReport,
        work_items: list[tuple[int, str]],
        fm_timeout_s: float,
        fm_query_timeout_ms: int,
    ) -> FMRefinedReport:
        """Run RD-01 fresh masking refinement on D1-INSECURE wires.

        Builds expressions once, then checks each insecure wire for
        single-bit XOR fresh masking via Z3 bijection queries.

        Only runs on masked mode circuits with insecure wires.
        """
        z3 = self._verifier._ensure_z3()
        fm_checker = FreshMaskingChecker(
            query_timeout_ms=fm_query_timeout_ms,
            module_timeout_s=fm_timeout_s,
        )

        # Build expressions once for FM queries.
        # MC-FM uses _build_expressions_mc (propagates through DFFs),
        # SC-FM uses _build_expressions (single-cycle, DFF Qs are free vars).
        s0_w, s1_w = adapter.s0_width, adapter.s1_width
        p_w = adapter.p_width
        s0 = z3.BitVec("s0", s0_w)
        s1 = z3.BitVec("s1", s1_w)
        p = z3.BitVec("p", p_w) if p_w > 0 else None
        if adapter.is_multi_cycle:
            expr = adapter._build_expressions_mc(s0, s1, None, p)
        else:
            expr = adapter._build_expressions(s0, s1, None, p)

        # Build wire_name → net_id lookup from work_items (Grok RD-01 MINOR fix:
        # removed unused net_to_name, use name_to_net for O(1) lookup below)
        name_to_net: dict[str, int] = {name: nid for nid, name in work_items}

        fm_results: dict[str, FMWireResult] = {}
        promoted = 0
        indeterminate = 0
        not_checked = 0
        timed_out = False

        fm_start = time.monotonic()

        for wire_name, d1_result in d1_report.results.items():
            # Only check D1-INSECURE wires
            if d1_result.verdict != SecurityVerdict.POTENTIALLY_INSECURE:
                fm_results[wire_name] = FMWireResult(
                    wire_name=wire_name,
                    d1_verdict=d1_result.verdict,
                    fm_verdict=FMVerdict.NOT_CHECKED,
                )
                not_checked += 1
                continue

            # Check module-level timeout
            if time.monotonic() - fm_start > fm_timeout_s:
                timed_out = True
                fm_results[wire_name] = FMWireResult(
                    wire_name=wire_name,
                    d1_verdict=d1_result.verdict,
                    fm_verdict=FMVerdict.INDETERMINATE,
                )
                indeterminate += 1
                continue

            # Find net_id for this wire (O(1) lookup via name_to_net)
            net_id = name_to_net.get(wire_name)

            if net_id is None or net_id not in expr:
                fm_results[wire_name] = FMWireResult(
                    wire_name=wire_name,
                    d1_verdict=d1_result.verdict,
                    fm_verdict=FMVerdict.INDETERMINATE,
                )
                indeterminate += 1
                continue

            # Get r bits in fan-in and run FM check
            r_bits = adapter.r_bits_in_fanin(net_id)
            wire_start = time.monotonic()
            verdict, masking_bit = fm_checker.check_wire(
                expr[net_id], r_bits, adapter,
                module_start_time=fm_start,
            )
            wire_elapsed = time.monotonic() - wire_start

            fm_results[wire_name] = FMWireResult(
                wire_name=wire_name,
                d1_verdict=d1_result.verdict,
                fm_verdict=verdict,
                masking_r_bit=masking_bit,
                fm_time_seconds=wire_elapsed,
            )

            if verdict == FMVerdict.SECURE:
                promoted += 1
            else:
                indeterminate += 1

        fm_elapsed = time.monotonic() - fm_start

        return FMRefinedReport(
            module_name=adapter.module_name,
            d1_report=d1_report,
            fm_results=fm_results,
            fm_promoted_count=promoted,
            fm_indeterminate_count=indeterminate,
            fm_not_checked_count=not_checked,
            fm_time_seconds=fm_elapsed,
            fm_timed_out=timed_out,
        )

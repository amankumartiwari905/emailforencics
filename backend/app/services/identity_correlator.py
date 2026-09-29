"""
Identity correlation and campaign attribution.

Maintains both:
1. A flat case_history list for direct case-to-case correlation
   (same public API as before -- email.py doesn't need to change).
2. A graph representation (NetworkX) where nodes are domains/IPs/URLs/
   case_ids and edges represent co-occurrence -- this enables real
   graph-based queries like "show me every case connected to this
   infrastructure, even indirectly through a chain of shared indicators."

Thread-safety note: FastAPI can run multiple requests concurrently
(via its threadpool for sync code paths), and both case_history and
correlation_graph are shared mutable state. All reads/writes to them
go through a lock to avoid race conditions -- e.g. two concurrent
requests both computing case_id from len(case_history) and generating
the same ID, or one request iterating case_history while another
appends to it.
"""

import logging
import threading
from dataclasses import dataclass, field

import networkx as nx

logger = logging.getLogger(__name__)

# Node types, used both to tag graph nodes and to build namespaced IDs
# below (so a domain and a URL that happen to be the same string can
# never collide into a single graph node).
NODE_TYPE_CASE = "case"
NODE_TYPE_DOMAIN = "domain"
NODE_TYPE_IP = "ip"
NODE_TYPE_URL = "url"


@dataclass
class CaseRecord:
    """One analyzed email's correlation-relevant indicators."""
    case_id: str
    domains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)


class IdentityCorrelator:
    """
    Encapsulates all correlation state behind a lock, instead of bare
    module-level globals -- makes the concurrency contract explicit
    and testable (you can instantiate a fresh correlator per test
    instead of fighting shared global state between test cases).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._case_history: list[CaseRecord] = []
        self._graph = nx.Graph()
        self._next_case_number = 1

    @staticmethod
    def _namespaced_id(node_type: str, value: str) -> str:
        """
        Prefixes each graph node ID with its type so that, e.g., a
        domain 'evil.com' and a URL 'evil.com' (edge case, but
        possible with malformed input) never collide into the same
        node. Case IDs are already unique by construction and don't
        need namespacing, but we namespace them too for consistency.
        """
        return f"{node_type}:{value}"

    def _add_node_if_missing(self, node_id: str, node_type: str) -> None:
        if not self._graph.has_node(node_id):
            self._graph.add_node(node_id, type=node_type)

    def _extract_indicators(self, email_data: dict) -> CaseRecord:
        """Pulls domains/IPs/URLs out of an analysis payload. Missing
        or malformed fields degrade to empty sets rather than raising,
        consistent with the rest of the pipeline's error-isolation
        philosophy."""
        domains: set[str] = set()
        ips: set[str] = set()
        urls: set[str] = set()

        domain_analysis = email_data.get("domain_analysis") or {}
        for key in ("sender_domain", "reply_to_domain", "return_path_domain"):
            value = domain_analysis.get(key)
            if value and isinstance(value, str):
                domains.add(value)

        for ip in email_data.get("unique_ips") or []:
            if isinstance(ip, str):
                ips.add(ip)

        for url in email_data.get("links") or []:
            if isinstance(url, str):
                urls.add(url)

        return CaseRecord(case_id="", domains=domains, ips=ips, urls=urls)

    def correlate_email(self, email_data: dict) -> dict:
        """
        Registers a new case, computes direct overlaps against every
        prior case, and updates the correlation graph.

        Returns:
            {
                "case_id": str,
                "related_cases": [{"case_id", "common_domains",
                                    "common_ips", "common_urls"}, ...],
                "correlation_found": bool,
            }
        """
        try:
            record = self._extract_indicators(email_data)
        except Exception:
            logger.exception("Failed to extract correlation indicators; "
                              "proceeding with an empty-indicator case")
            record = CaseRecord(case_id="")

        with self._lock:
            case_id = f"CASE-{self._next_case_number:04d}"
            self._next_case_number += 1
            record.case_id = case_id

            matches = []
            for prior in self._case_history:
                common_domains = record.domains & prior.domains
                common_ips = record.ips & prior.ips
                common_urls = record.urls & prior.urls

                if common_domains or common_ips or common_urls:
                    matches.append({
                        "case_id": prior.case_id,
                        "common_domains": sorted(common_domains),
                        "common_ips": sorted(common_ips),
                        "common_urls": sorted(common_urls),
                    })

            self._case_history.append(record)

            # --- Update graph ---
            case_node = self._namespaced_id(NODE_TYPE_CASE, case_id)
            self._add_node_if_missing(case_node, NODE_TYPE_CASE)

            for domain in record.domains:
                node = self._namespaced_id(NODE_TYPE_DOMAIN, domain)
                self._add_node_if_missing(node, NODE_TYPE_DOMAIN)
                self._graph.add_edge(case_node, node)

            for ip in record.ips:
                node = self._namespaced_id(NODE_TYPE_IP, ip)
                self._add_node_if_missing(node, NODE_TYPE_IP)
                self._graph.add_edge(case_node, node)

            for url in record.urls:
                node = self._namespaced_id(NODE_TYPE_URL, url)
                self._add_node_if_missing(node, NODE_TYPE_URL)
                self._graph.add_edge(case_node, node)

        return {
            "case_id": case_id,
            "related_cases": matches,
            "correlation_found": len(matches) > 0,
        }

    def get_campaign_cluster(self, case_id: str) -> dict | None:
        """
        Returns the full connected component (campaign cluster)
        containing this case -- every case, domain, IP, and URL
        reachable through any chain of shared indicators, not just
        direct one-hop matches.

        Case A and Case C might share nothing directly, but if Case B
        shares a domain with A and an IP with C, all three belong to
        the same campaign -- this is what graph-based correlation
        catches that flat matching misses.
        """
        case_node = self._namespaced_id(NODE_TYPE_CASE, case_id)

        with self._lock:
            if case_node not in self._graph:
                return None

            component = nx.node_connected_component(self._graph, case_node)
            subgraph = self._graph.subgraph(component)

            nodes = self._serialize_nodes(subgraph)
            edges = self._serialize_edges(subgraph)

        case_ids = [n["id"] for n in nodes if n["type"] == NODE_TYPE_CASE]

        return {
            "cluster_size": len(case_ids),
            "case_ids": case_ids,
            "nodes": nodes,
            "edges": edges,
        }

    def get_full_graph(self) -> dict:
        """Returns the entire correlation graph -- useful for a global
        campaign-overview visualization on the dashboard."""
        with self._lock:
            nodes = self._serialize_nodes(self._graph)
            edges = self._serialize_edges(self._graph)
        return {"nodes": nodes, "edges": edges}

    @staticmethod
    def _serialize_nodes(graph: nx.Graph) -> list[dict]:
        """Strips the internal 'type:' namespace prefix back off before
        returning to callers, so API responses show clean values
        ('evil.com', not 'domain:evil.com')."""
        result = []
        for node_id, attrs in graph.nodes(data=True):
            node_type = attrs.get("type", "unknown")
            display_id = node_id.split(":", 1)[1] if ":" in node_id else node_id
            result.append({"id": display_id, "type": node_type})
        return result

    @staticmethod
    def _serialize_edges(graph: nx.Graph) -> list[dict]:
        result = []
        for u, v in graph.edges():
            source = u.split(":", 1)[1] if ":" in u else u
            target = v.split(":", 1)[1] if ":" in v else v
            result.append({"source": source, "target": target})
        return result


# Module-level singleton, preserving the original function-based API
# so email.py's imports (correlate_email, get_campaign_cluster,
# get_full_graph) keep working unchanged.
_correlator = IdentityCorrelator()


def correlate_email(email_data: dict) -> dict:
    return _correlator.correlate_email(email_data)


def get_campaign_cluster(case_id: str) -> dict | None:
    return _correlator.get_campaign_cluster(case_id)


def get_full_graph() -> dict:
    return _correlator.get_full_graph()
"""Load and query MITRE ATT&CK STIX 2.1 data."""

import json
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger()


class STIXDataStore:
    """
    Load and query MITRE ATT&CK STIX 2.1 data.

    Provides efficient lookup of technique metadata, tactics,
    and relationships from the ATT&CK knowledge base.
    """

    def __init__(self, stix_path: str | Path | None = None):
        """
        Initialize STIX data store.

        Args:
            stix_path: Path to enterprise-attack.json STIX file.
                       If None, searches default locations.
        """
        self.stix_path: Path | None = None
        self.bundle: dict[str, Any] = {}
        self.techniques: dict[str, dict[str, Any]] = {}
        self.tactics: dict[str, dict[str, Any]] = {}
        self.relationships: list[dict[str, Any]] = []
        self._loaded = False

        if stix_path:
            self.load(stix_path)

    def load(self, stix_path: str | Path) -> None:
        """
        Load STIX data from file.

        Args:
            stix_path: Path to enterprise-attack.json

        Raises:
            FileNotFoundError: If STIX file not found
            json.JSONDecodeError: If file is not valid JSON
        """
        path = Path(stix_path)
        if not path.exists():
            raise FileNotFoundError(f"STIX data file not found: {path}")

        log.info("loading_stix_data", path=str(path))

        with open(path, "r", encoding="utf-8") as f:
            self.bundle = json.load(f)

        self._index_objects()
        self._loaded = True

        log.info(
            "stix_data_loaded",
            techniques=len(self.techniques),
            tactics=len(self.tactics),
            relationships=len(self.relationships),
        )

    def _index_objects(self) -> None:
        """Index STIX objects for fast lookup."""
        objects = self.bundle.get("objects", [])

        for obj in objects:
            obj_type = obj.get("type")
            external_refs = obj.get("external_references", [])

            # Extract ATT&CK ID from external references
            attack_id = None
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    attack_id = ref.get("external_id")
                    break

            if not attack_id:
                continue

            if obj_type == "attack-pattern":
                # Extract tactic from kill chain phases
                tactic = None
                kill_chain_phases = obj.get("kill_chain_phases", [])
                for phase in kill_chain_phases:
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactic = phase.get("phase_name")
                        break

                self.techniques[attack_id] = {
                    "id": obj.get("id"),
                    "technique_id": attack_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "tactic": tactic,
                    "url": self._build_mitre_url(attack_id),
                    "aliases": obj.get("aliases", []),
                    "data_sources": obj.get("x_mitre_data_sources", []),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "permissions_required": obj.get("x_mitre_permissions_required", []),
                }

            elif obj_type == "x-mitre-tactic":
                self.tactics[attack_id] = {
                    "id": obj.get("id"),
                    "tactic_id": attack_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "shortname": obj.get("x_mitre_shortname", ""),
                    "url": self._build_mitre_url(attack_id),
                }

        # Index relationships
        self.relationships = [
            obj for obj in objects if obj.get("type") == "relationship"
        ]

    @staticmethod
    def _build_mitre_url(technique_id: str) -> str:
        """Build MITRE ATT&CK URL for a technique."""
        return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"

    def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        """
        Get technique metadata by ID.

        Args:
            technique_id: ATT&CK technique ID (e.g., "T1059.001")

        Returns:
            Technique metadata dict or None if not found
        """
        return self.techniques.get(technique_id)

    def get_tactic(self, tactic_id: str) -> dict[str, Any] | None:
        """
        Get tactic metadata by ID.

        Args:
            tactic_id: ATT&CK tactic ID (e.g., "execution")

        Returns:
            Tactic metadata dict or None if not found
        """
        return self.tactics.get(tactic_id)

    def search_techniques(
        self,
        query: str,
        tactic: str | None = None,
        platform: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Search techniques by name, description, or ID.

        Args:
            query: Search query (case-insensitive)
            tactic: Optional filter by tactic
            platform: Optional filter by platform

        Returns:
            List of matching technique metadata dicts
        """
        query_lower = query.lower()
        results = []

        for tech_id, tech in self.techniques.items():
            # Filter by tactic
            if tactic and tech.get("tactic") != tactic:
                continue

            # Filter by platform
            if platform:
                platforms = [p.lower() for p in tech.get("platforms", [])]
                if not any(platform.lower() in p for p in platforms):
                    continue

            # Search in name, description, aliases
            searchable = (
                tech.get("name", "").lower()
                + " "
                + tech.get("description", "").lower()
                + " "
                + " ".join(tech.get("aliases", []))
            )

            if query_lower in searchable or query_lower in tech_id.lower():
                results.append(tech)

        return results

    def get_techniques_by_tactic(self, tactic: str) -> list[dict[str, Any]]:
        """
        Get all techniques for a specific tactic.

        Args:
            tactic: Tactic name (e.g., "execution", "persistence")

        Returns:
            List of technique metadata dicts
        """
        return [
            tech for tech in self.techniques.values()
            if tech.get("tactic") == tactic.lower()
        ]

    def get_subtechniques(self, parent_id: str) -> list[dict[str, Any]]:
        """
        Get subtechniques of a parent technique.

        Args:
            parent_id: Parent technique ID (e.g., "T1059")

        Returns:
            List of subtechnique metadata dicts
        """
        # Subtechniques have IDs like T1059.001, T1059.002, etc.
        prefix = parent_id + "."
        return [
            tech for tech_id, tech in self.techniques.items()
            if tech_id.startswith(prefix)
        ]

    def get_related_techniques(
        self,
        technique_id: str,
        relationship_type: str = "subtechnique-of",
    ) -> list[dict[str, Any]]:
        """
        Get techniques related to a given technique.

        Args:
            technique_id: Source technique ID
            relationship_type: Type of relationship to filter

        Returns:
            List of related technique metadata dicts
        """
        related = []

        for rel in self.relationships:
            if rel.get("relationship_type") != relationship_type:
                continue

            source_ref = rel.get("source_ref", "")
            target_ref = rel.get("target_ref", "")

            # Find the technique object for the target
            target_id = target_ref.replace("attack-pattern--", "")
            for tech in self.techniques.values():
                if tech.get("id") == target_ref:
                    related.append(tech)
                    break

        return related

    def get_all_tactics(self) -> list[dict[str, Any]]:
        """Get all tactics."""
        return list(self.tactics.values())

    def get_all_techniques(self) -> list[dict[str, Any]]:
        """Get all techniques."""
        return list(self.techniques.values())

    @property
    def is_loaded(self) -> bool:
        """Check if STIX data is loaded."""
        return self._loaded


def load_stix_data(
    search_paths: list[str | Path] | None = None,
) -> STIXDataStore:
    """
    Load STIX data from default or custom paths.

    Args:
        search_paths: List of paths to search for STIX data.
                      If None, uses default locations.

    Returns:
        Loaded STIXDataStore instance

    Raises:
        FileNotFoundError: If STIX data not found in any path
    """
    if search_paths is None:
        search_paths = [
            Path(__file__).parent.parent.parent / "data" / "attack_stix" / "enterprise-attack.json",
            Path("/app/data/attack_stix/enterprise-attack.json"),
            Path("./data/attack_stix/enterprise-attack.json"),
        ]

    for path in search_paths:
        if Path(path).exists():
            store = STIXDataStore(path)
            return store

    raise FileNotFoundError(
        "STIX data not found. Download enterprise-attack.json from "
        "https://github.com/mitre-attack/attack-stix-data"
    )

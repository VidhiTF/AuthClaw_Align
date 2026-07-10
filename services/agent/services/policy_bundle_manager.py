import hashlib
import json
import os
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from database import engine
from policy import compile_policy_to_rego, get_policy


class PolicyBundleManager:
    """Builds and tracks OPA bundle artifacts without making OPA mandatory locally."""

    def __init__(self, bundle_dir: Optional[str] = None):
        self.bundle_dir = Path(bundle_dir or os.getenv("AUTHCLAW_POLICY_BUNDLE_DIR", "var/policy_bundles"))
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        self.active_marker = self.bundle_dir / "active_bundle.json"

    def list_bundles(self, tenant_id: int) -> Dict[str, Any]:
        bundles = []
        for manifest_path in sorted(self.bundle_dir.glob(f"tenant-{tenant_id}-*.manifest.json"), reverse=True):
            try:
                bundles.append(json.loads(manifest_path.read_text(encoding="utf-8")))
            except Exception:
                continue
        active = self.active_bundle(tenant_id)
        return {
            "tenant_id": tenant_id,
            "active_bundle": active,
            "bundles": bundles,
            "policy_version_history": self.policy_version_history(tenant_id),
            "yaml_fallback": True,
        }

    def build_bundle(self, tenant_id: int, actor: str = "system") -> Dict[str, Any]:
        policies = self._tenant_policies(tenant_id)
        yaml_policy = get_policy()
        rego = compile_policy_to_rego(yaml_policy)
        payload = {
            "tenant_id": tenant_id,
            "built_at": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "yaml_policy": yaml_policy,
            "tenant_policies": policies,
            "rego_package": (yaml_policy.get("opa") or {}).get("package", "authclaw.policy"),
        }
        canonical = json.dumps(payload, sort_keys=True, default=str)
        version = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        base = f"tenant-{tenant_id}-{version}"
        bundle_path = self.bundle_dir / f"{base}.tar.gz"
        manifest_path = self.bundle_dir / f"{base}.manifest.json"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "policy.rego").write_text(rego, encoding="utf-8")
            (tmp_path / "data.json").write_text(json.dumps({"authclaw": payload}, indent=2, default=str), encoding="utf-8")
            (tmp_path / ".manifest").write_text(
                json.dumps({"revision": version, "roots": ["authclaw"]}, indent=2),
                encoding="utf-8",
            )
            with tarfile.open(bundle_path, "w:gz") as tar:
                tar.add(tmp_path / "policy.rego", arcname="policy.rego")
                tar.add(tmp_path / "data.json", arcname="data.json")
                tar.add(tmp_path / ".manifest", arcname=".manifest")

        digest = hashlib.sha256(bundle_path.read_bytes()).hexdigest()
        manifest = {
            "tenant_id": tenant_id,
            "bundle_id": version,
            "version": version,
            "status": "built",
            "artifact": str(bundle_path),
            "sha256": digest,
            "built_at": payload["built_at"],
            "built_by": actor,
            "policy_count": len(policies),
            "metadata": {
                "rego_package": payload["rego_package"],
                "yaml_fallback": True,
                "opa_bundle_format": "tar.gz",
            },
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
        return manifest

    def promote_bundle(self, tenant_id: int, bundle_id: str, actor: str = "system") -> Dict[str, Any]:
        manifest = self._load_manifest(tenant_id, bundle_id)
        manifest["status"] = "active"
        manifest["promoted_at"] = datetime.now(timezone.utc).isoformat()
        manifest["promoted_by"] = actor
        self._write_manifest(manifest)
        active_map = self._active_map()
        active_map[str(tenant_id)] = {
            "bundle_id": bundle_id,
            "sha256": manifest["sha256"],
            "artifact": manifest["artifact"],
            "promoted_at": manifest["promoted_at"],
            "promoted_by": actor,
        }
        self.active_marker.write_text(json.dumps(active_map, indent=2, default=str), encoding="utf-8")
        return manifest

    def rollback_bundle(self, tenant_id: int, actor: str = "system") -> Dict[str, Any]:
        bundles = [item for item in self.list_bundles(tenant_id)["bundles"] if item.get("status") in {"built", "active"}]
        active = self.active_bundle(tenant_id)
        candidates = [item for item in bundles if item.get("bundle_id") != (active or {}).get("bundle_id")]
        if not candidates:
            raise ValueError("No previous bundle is available for rollback.")
        previous = sorted(candidates, key=lambda item: item.get("built_at") or "", reverse=True)[0]
        previous["rollback_from"] = active.get("bundle_id") if active else None
        return self.promote_bundle(tenant_id, previous["bundle_id"], actor=actor)

    def active_bundle(self, tenant_id: int) -> Optional[Dict[str, Any]]:
        return self._active_map().get(str(tenant_id))

    def policy_version_history(self, tenant_id: int) -> List[Dict[str, Any]]:
        with engine.connect() as conn:
            rows = conn.execute(
                text("""
                    SELECT pv.id, pv.policy_id, p.name, pv.version, pv.status, pv.checksum,
                           pv.author, pv.approver, pv.changelog, pv.created_at, pv.published_at
                    FROM policy_versions pv
                    LEFT JOIN policies p ON p.id = pv.policy_id
                    WHERE pv.tenant_id = :tenant_id
                    ORDER BY pv.created_at DESC NULLS LAST, pv.id DESC
                    LIMIT 100
                """),
                {"tenant_id": tenant_id},
            ).fetchall()
        return [
            {
                "id": row.id,
                "policy_id": row.policy_id,
                "policy_name": row.name,
                "version": row.version,
                "status": row.status,
                "checksum": row.checksum,
                "author": row.author,
                "approver": row.approver,
                "changelog": row.changelog,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "published_at": row.published_at.isoformat() if row.published_at else None,
            }
            for row in rows
        ]

    def _tenant_policies(self, tenant_id: int) -> List[Dict[str, Any]]:
        with engine.connect() as conn:
            rows = conn.execute(
                text("""
                    SELECT id, name, type, rules, enabled, status, version, severity_level, updated_at
                    FROM policies
                    WHERE tenant_id = :tenant_id
                    ORDER BY id
                """),
                {"tenant_id": tenant_id},
            ).fetchall()
        policies = []
        for row in rows:
            try:
                rules = json.loads(row.rules) if isinstance(row.rules, str) else row.rules
            except Exception:
                rules = {"raw": row.rules}
            policies.append({
                "id": row.id,
                "name": row.name,
                "type": row.type,
                "rules": rules,
                "enabled": row.enabled,
                "status": row.status,
                "version": row.version,
                "severity_level": row.severity_level,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            })
        return policies

    def _active_map(self) -> Dict[str, Any]:
        if not self.active_marker.exists():
            return {}
        try:
            return json.loads(self.active_marker.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _manifest_path(self, tenant_id: int, bundle_id: str) -> Path:
        return self.bundle_dir / f"tenant-{tenant_id}-{bundle_id}.manifest.json"

    def _load_manifest(self, tenant_id: int, bundle_id: str) -> Dict[str, Any]:
        path = self._manifest_path(tenant_id, bundle_id)
        if not path.exists():
            raise ValueError("Policy bundle not found.")
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_manifest(self, manifest: Dict[str, Any]) -> None:
        path = self._manifest_path(int(manifest["tenant_id"]), str(manifest["bundle_id"]))
        path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")

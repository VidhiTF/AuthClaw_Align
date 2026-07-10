from typing import List, Tuple

from redaction import redact_sensitive_data_rich


class ResponseInspectionService:
    def inspect(self, response: str, username: str, tenant_id=None) -> Tuple[str, List[dict]]:
        return redact_sensitive_data_rich(response, username, tenant_id)

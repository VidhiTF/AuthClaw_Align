import pathlib
import re
import unittest


class RetiredControlPlaneRouteSmokeTests(unittest.TestCase):
    def test_temporary_control_plane_routes_stay_removed(self):
        source = (pathlib.Path(__file__).parents[1] / "main.py").read_text(encoding="utf-8")
        paths = re.findall(r'@app\.(?:get|post|put|patch|delete)\("([^"]+)"', source)
        retired_prefixes = (
            "/auth",
            "/identity",
            "/providers",
            "/routes",
            "/tenants",
            "/keys",
            "/provider-credentials",
        )

        self.assertFalse([path for path in paths if path.startswith(retired_prefixes)])
        self.assertNotIn("/.well-known/jwks.json", paths)
        self.assertNotIn("/.well-known/openid-configuration", paths)


if __name__ == "__main__":
    unittest.main()

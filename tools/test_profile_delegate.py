"""Plugin-only delegation smoke test; no real profile or vault is accessed."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class ProfileDelegateSmoke(unittest.TestCase):
    def test_plugin_only_install_preserves_the_owner_arguments(self):
        binary = Path(os.environ.get("PROFILE_DELEGATE_BINARY", "target/release/bitwarden-use")).resolve()
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            owner = home / ".claude/plugins/cache/fixture/profile-use/0.4.0"
            scripts = owner / "scripts"
            scripts.mkdir(parents=True)
            (scripts / "profile_vault_sync.py").write_text("# synthetic sync owner\n")
            (scripts / "profile_use.py").write_text(
                "import json, os, sys\nfrom pathlib import Path\n"
                "print(json.dumps({'args':sys.argv[1:],'binary':Path(os.environ['PROFILE_SYNC_BWU']).name}))\n"
            )
            registry = home / ".claude/plugins/installed_plugins.json"
            registry.write_text(json.dumps({"plugins": {"profile-use@fixture": [{"installPath": str(owner)}]}}))
            source = home / "fixture.profile.json"
            source.write_text('{"profile_name":"fixture"}\n')
            env = dict(os.environ, HOME=str(home), USE_NO_UPDATE_CHECK="1",
                       XDG_CONFIG_HOME=str(home / "config"), XDG_CACHE_HOME=str(home / "cache"),
                       XDG_DATA_HOME=str(home / "data"))
            result = subprocess.run([str(binary), "profile", "sync", str(source), "--profile", "fixture",
                                     "--folder", "Example", "--skip-attachments", "--dry-run"],
                                    env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {
                "binary": "bitwarden-use",
                "args": ["sync", "--file", str(source), "--folder", "Example", "--profile", "fixture",
                         "--skip-attachments", "--dry-run"],
            })
            self.assertFalse((home / "data/rbw").exists())


if __name__ == "__main__":
    unittest.main()

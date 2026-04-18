import unittest
from pathlib import Path


class DockerImageContractTests(unittest.TestCase):
    def test_dockerfile_uses_repo_source_and_runtime_entrypoint(self):
        content = Path("docker/Dockerfile").read_text()

        self.assertIn("COPY . /src/inspircd", content)
        self.assertIn("COPY --chown=inspircd:inspircd docker/custom_entrypoint.sh /inspircd/custom_entrypoint.sh", content)
        self.assertIn('ENTRYPOINT ["/bin/sh", "/inspircd/custom_entrypoint.sh"]', content)

    def test_entrypoint_requires_mounted_config(self):
        content = Path("docker/custom_entrypoint.sh").read_text()

        self.assertIn('config_file="/inspircd/conf/inspircd.conf"', content)
        self.assertIn('echo "Missing required InspIRCd config: $config_file" >&2', content)
        self.assertIn('exec /inspircd/bin/inspircd --nofork "$@"', content)
        self.assertNotIn("/inspircd/scripts/", content)


if __name__ == "__main__":
    unittest.main()

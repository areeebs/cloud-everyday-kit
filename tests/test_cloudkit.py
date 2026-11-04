import json
import importlib.util
import tempfile
import unittest
from pathlib import Path

import cloudkit


class CloudKitTests(unittest.TestCase):
    def write_temp(self, content: str) -> Path:
        temporary = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
        with temporary:
            temporary.write(content)
        self.addCleanup(Path(temporary.name).unlink, missing_ok=True)
        return Path(temporary.name)

    def test_iam_detects_partial_action_and_resource_wildcards(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:Get*",
                "Resource": "arn:aws:s3:::example-bucket/*",
            }]
        }
        path = self.write_temp(json.dumps(policy))
        rules = {item.rule for item in cloudkit.analyze_iam(path)}
        self.assertEqual(rules, {"IAM002", "IAM003"})

    def test_iam_requires_statements_and_objects(self):
        missing = self.write_temp("{}")
        malformed = self.write_temp('{"Statement": ["not-an-object"]}')
        with self.assertRaisesRegex(ValueError, "must include a Statement"):
            cloudkit.analyze_iam(missing)
        with self.assertRaisesRegex(ValueError, "Every IAM policy Statement"):
            cloudkit.analyze_iam(malformed)

    def test_iam_flags_wildcard_passrole_scope(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::123456789012:role/*",
            }]
        }
        path = self.write_temp(json.dumps(policy))
        rules = {item.rule for item in cloudkit.analyze_iam(path)}
        self.assertIn("IAM004", rules)
        self.assertIn("IAM003", rules)

    def test_iam_flags_passrole_action_patterns(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:Pass*",
                "Resource": "*",
            }]
        }
        path = self.write_temp(json.dumps(policy))
        rules = {item.rule for item in cloudkit.analyze_iam(path)}
        self.assertIn("IAM004", rules)

    def test_cost_rejects_non_finite_values(self):
        path = self.write_temp("period,service,cost\n2026-01,Compute,nan\n2026-02,Compute,2\n")
        with self.assertRaisesRegex(ValueError, "finite number"):
            cloudkit.analyze_cost(path, 10)

    def test_cost_sums_duplicate_service_period_rows(self):
        path = self.write_temp(
            "period,service,cost\n"
            "2026-01,Compute,1.00\n"
            "2026-01,Compute,2.00\n"
            "2026-02,Compute,5.00\n"
        )
        report = cloudkit.analyze_cost(path, 10)
        self.assertEqual(report["changes"][0]["previous"], 3.0)
        self.assertEqual(report["changes"][0]["current"], 5.0)
        self.assertEqual(report["changes"][0]["change"], 2.0)

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML is not installed")
    def test_kubernetes_example_does_not_treat_service_as_a_pod(self):
        root = Path(__file__).resolve().parents[1]
        findings = cloudkit.analyze_kubernetes([root / "examples/workload.yaml"])
        pod_findings = [item for item in findings if item.rule == "KUBE003"]
        self.assertEqual(len(pod_findings), 1)
        self.assertIn("Deployment/sample-web", pod_findings[0].subject)
        self.assertIn("KUBE001", {item.rule for item in findings})

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML is not installed")
    def test_kubernetes_container_override_can_disable_pod_non_root(self):
        path = self.write_temp(
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n  name: override-example\n"
            "spec:\n"
            "  securityContext:\n    runAsNonRoot: true\n"
            "  containers:\n"
            "    - name: app\n"
            "      image: example/app:1\n"
            "      securityContext:\n        runAsNonRoot: false\n"
        )
        findings = cloudkit.analyze_kubernetes([path])
        self.assertIn("KUBE003", {item.rule for item in findings})


if __name__ == "__main__":
    unittest.main()

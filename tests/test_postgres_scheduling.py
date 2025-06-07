#!/usr/bin/env python3
"""
Test PostgreSQL scheduling configurations in Helm chart.
"""

import unittest
import subprocess
import tempfile
import os
import yaml


class TestPostgresScheduling(unittest.TestCase):
    """Test PostgreSQL scheduling configurations in Helm chart."""

    def setUp(self):
        """Set up test environment."""
        self.chart_path = os.path.join(
            os.path.dirname(__file__), "..", "chart", "kronic"
        )

    def _helm_template(self, values=None):
        """Run helm template and return the parsed YAML output."""
        cmd = ["helm", "template", "test", self.chart_path, "--dry-run"]

        if values:
            for key, value in values.items():
                cmd.extend(["--set", f"{key}={value}"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(f"Helm template failed: {result.stderr}")

        # Parse the YAML output
        documents = list(yaml.safe_load_all(result.stdout))
        return documents

    def _get_postgres_statefulset(self, documents):
        """Find the PostgreSQL StatefulSet in the documents."""
        for doc in documents:
            if (
                doc
                and doc.get("kind") == "StatefulSet"
                and doc.get("metadata", {}).get("name", "").endswith("-postgres")
            ):
                return doc
        return None

    def test_postgres_is_statefulset(self):
        """Test that PostgreSQL is deployed as a StatefulSet."""
        documents = self._helm_template()
        postgres_sts = self._get_postgres_statefulset(documents)

        self.assertIsNotNone(postgres_sts, "PostgreSQL StatefulSet not found")
        self.assertEqual(postgres_sts["kind"], "StatefulSet")
        self.assertTrue(postgres_sts["metadata"]["name"].endswith("-postgres"))

    def test_default_scheduling_empty(self):
        """Test that scheduling configurations are not present with default empty values."""
        documents = self._helm_template()
        postgres_sts = self._get_postgres_statefulset(documents)

        self.assertIsNotNone(postgres_sts, "PostgreSQL StatefulSet not found")

        spec = postgres_sts["spec"]["template"]["spec"]

        # With empty default values, these keys should not be present
        self.assertNotIn(
            "affinity", spec, "affinity should not be present with empty default values"
        )
        self.assertNotIn(
            "tolerations",
            spec,
            "tolerations should not be present with empty default values",
        )
        self.assertNotIn(
            "nodeSelector",
            spec,
            "nodeSelector should not be present with empty default values",
        )

    def test_nodeSelector_configuration(self):
        """Test that nodeSelector configuration is properly templated."""
        values = {
            "database.nodeSelector.node-type": "database",
            "database.nodeSelector.zone": "us-west-2a",
        }

        documents = self._helm_template(values)
        postgres_sts = self._get_postgres_statefulset(documents)

        self.assertIsNotNone(postgres_sts, "PostgreSQL StatefulSet not found")

        spec = postgres_sts["spec"]["template"]["spec"]
        self.assertIn("nodeSelector", spec)

        node_selector = spec["nodeSelector"]
        self.assertEqual(node_selector["node-type"], "database")
        self.assertEqual(node_selector["zone"], "us-west-2a")

    def test_tolerations_configuration(self):
        """Test that tolerations configuration is properly templated."""
        values = {
            "database.tolerations[0].key": "node-type",
            "database.tolerations[0].operator": "Equal",
            "database.tolerations[0].value": "database",
            "database.tolerations[0].effect": "NoSchedule",
        }

        documents = self._helm_template(values)
        postgres_sts = self._get_postgres_statefulset(documents)

        self.assertIsNotNone(postgres_sts, "PostgreSQL StatefulSet not found")

        spec = postgres_sts["spec"]["template"]["spec"]
        self.assertIn("tolerations", spec)

        tolerations = spec["tolerations"]
        self.assertEqual(len(tolerations), 1)

        toleration = tolerations[0]
        self.assertEqual(toleration["key"], "node-type")
        self.assertEqual(toleration["operator"], "Equal")
        self.assertEqual(toleration["value"], "database")
        self.assertEqual(toleration["effect"], "NoSchedule")

    def test_affinity_configuration(self):
        """Test that affinity configuration is properly templated."""
        values = {
            "database.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key": "node-type",
            "database.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator": "In",
            "database.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]": "database",
        }

        documents = self._helm_template(values)
        postgres_sts = self._get_postgres_statefulset(documents)

        self.assertIsNotNone(postgres_sts, "PostgreSQL StatefulSet not found")

        spec = postgres_sts["spec"]["template"]["spec"]
        self.assertIn("affinity", spec)

        affinity = spec["affinity"]
        self.assertIn("nodeAffinity", affinity)

        node_affinity = affinity["nodeAffinity"]
        self.assertIn("requiredDuringSchedulingIgnoredDuringExecution", node_affinity)

        required = node_affinity["requiredDuringSchedulingIgnoredDuringExecution"]
        self.assertIn("nodeSelectorTerms", required)

        terms = required["nodeSelectorTerms"]
        self.assertEqual(len(terms), 1)

        term = terms[0]
        self.assertIn("matchExpressions", term)

        expressions = term["matchExpressions"]
        self.assertEqual(len(expressions), 1)

        expression = expressions[0]
        self.assertEqual(expression["key"], "node-type")
        self.assertEqual(expression["operator"], "In")
        self.assertEqual(expression["values"], ["database"])

    def test_combined_scheduling_configuration(self):
        """Test that all scheduling configurations work together."""
        values = {
            "database.nodeSelector.node-type": "database",
            "database.tolerations[0].key": "node-type",
            "database.tolerations[0].operator": "Equal",
            "database.tolerations[0].value": "database",
            "database.tolerations[0].effect": "NoSchedule",
            "database.affinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].weight": "100",
            "database.affinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].preference.matchExpressions[0].key": "zone",
            "database.affinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].preference.matchExpressions[0].operator": "In",
            "database.affinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].preference.matchExpressions[0].values[0]": "us-west-2a",
        }

        documents = self._helm_template(values)
        postgres_sts = self._get_postgres_statefulset(documents)

        self.assertIsNotNone(postgres_sts, "PostgreSQL StatefulSet not found")

        spec = postgres_sts["spec"]["template"]["spec"]

        # Verify all three scheduling configurations are present
        self.assertIn("nodeSelector", spec)
        self.assertIn("tolerations", spec)
        self.assertIn("affinity", spec)

        # Verify nodeSelector
        self.assertEqual(spec["nodeSelector"]["node-type"], "database")

        # Verify tolerations
        self.assertEqual(len(spec["tolerations"]), 1)
        self.assertEqual(spec["tolerations"][0]["key"], "node-type")

        # Verify affinity
        affinity = spec["affinity"]["nodeAffinity"]
        self.assertIn("preferredDuringSchedulingIgnoredDuringExecution", affinity)
        preferred = affinity["preferredDuringSchedulingIgnoredDuringExecution"][0]
        self.assertEqual(preferred["weight"], 100)
        self.assertEqual(preferred["preference"]["matchExpressions"][0]["key"], "zone")


if __name__ == "__main__":
    unittest.main()

import sys
from pathlib import Path
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / ".github" / "scripts"))

import generate_loc_report


class GenerateLocReportTests(unittest.TestCase):
    def test_crate_name_for_path_uses_workspace_crate(self) -> None:
        self.assertEqual(generate_loc_report.crate_name_for_path("./merkle-core/src/lib.rs"), "merkle-core")
        self.assertEqual(generate_loc_report.crate_name_for_path("./merkle-variants/tests/binary.rs"), "merkle-variants")
        self.assertEqual(generate_loc_report.crate_name_for_path("./website/src/index.html"), "website")

    def test_weekly_summary_contains_expected_sections(self) -> None:
        summary = generate_loc_report.build_weekly_summary(
            date_label="2026-06-15",
            commit_sha="949abfd",
            repo_url="https://github.com/dicethedev/MerkleForge",
            crates=[("merkle-core", 100), ("merkle-variants", 80)],
            no_tests_total=180,
            with_tests_total=260,
        )

        self.assertIn("Weekly MerkleForge LoC Report", summary)
        self.assertIn("Date: 2026-06-15 • Commit: 949abfd", summary)
        self.assertIn("Per-crate (no tests)", summary)
        self.assertIn("**merkle-core**: 100", summary)
        self.assertIn("**Total Rust LoC (no tests):** 180", summary)
        self.assertIn("**Total Rust LoC (with tests):** 260", summary)


if __name__ == "__main__":
    unittest.main()

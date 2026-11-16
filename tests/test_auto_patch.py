import tempfile
import unittest
from pathlib import Path

from utils.auto_patch import apply_patch_plan, create_patch_plan


class AutoPatchTests(unittest.TestCase):
    def test_preview_and_apply_only_explicit_safe_fixes(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "schema.sql").write_text(
                "CREATE TABLE public.accounts (id integer);\n",
                encoding="utf-8",
            )
            (root / "client.ts").write_text(
                "const key = process.env.NEXT_PUBLIC_STRIPE_SECRET;\n",
                encoding="utf-8",
            )
            (root / ".env.local").write_text("SECRET=value\n", encoding="utf-8")
            findings = [
                {"rule_id": "DB-004", "file_path": "schema.sql", "snippet": "CREATE TABLE public.accounts"},
                {"rule_id": "ENV-001", "file_path": "client.ts", "line_number": 1},
                {"rule_id": "ENV-002", "file_path": ".env.local"},
            ]

            plan = create_patch_plan(root, findings)

            self.assertIn("ALTER TABLE \"public\".\"accounts\" ENABLE ROW LEVEL SECURITY;", plan.unified_diff)
            self.assertIn("NEXT_PUBLIC_STRIPE_SECRET", plan.unified_diff)
            self.assertEqual(len(plan.files), 3)
            applied = apply_patch_plan(root, plan)

            self.assertCountEqual(applied, ["schema.sql", "client.ts", ".gitignore"])
            self.assertIn("ALTER TABLE \"public\".\"accounts\"", (root / "schema.sql").read_text())
            self.assertNotIn("NEXT_PUBLIC_", (root / "client.ts").read_text())
            self.assertIn("!.env.example", (root / ".gitignore").read_text())

    def test_rejects_files_changed_after_preview(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "client.ts"
            target.write_text("const key = process.env.NEXT_PUBLIC_SECRET;\n", encoding="utf-8")
            plan = create_patch_plan(root, [{
                "rule_id": "ENV-001",
                "file_path": "client.ts",
                "line_number": 1,
            }])
            target.write_text("const key = process.env.OTHER_VALUE;\n", encoding="utf-8")

            with self.assertRaises(RuntimeError):
                apply_patch_plan(root, plan)

    def test_skips_public_prefixes_inside_comments(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / "client.ts"
            target.write_text("// process.env.NEXT_PUBLIC_SECRET\n", encoding="utf-8")

            plan = create_patch_plan(root, [{
                "rule_id": "ENV-001",
                "file_path": "client.ts",
                "line_number": 1,
            }])

            self.assertFalse(plan.files)
            self.assertTrue(any("inside a comment" in entry for entry in plan.skipped))


if __name__ == "__main__":
    unittest.main()

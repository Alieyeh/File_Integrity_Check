from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from file_integrity_monitor.config import ExclusionConfig, ScanSettings, load_exclusions_file
from file_integrity_monitor.scanner import ScanError, scan_files


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.base = Path(self.tempdir.name)
        self.root = self.base / "root"
        self.root.mkdir()
        self.db = self.base / "state.sqlite3"
        self.outdir = self.base / "reports"

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _settings(self, *, hash_new_files: bool = True, exclusions: ExclusionConfig | None = None) -> ScanSettings:
        return ScanSettings(
            root=self.root,
            db=self.db,
            outdir=self.outdir,
            max_workers=1,
            sample_bytes=4,
            hash_new_files=hash_new_files,
            history_retention_per_path=5,
            exclusions=exclusions
            or ExclusionConfig(
                dir_names=frozenset(),
                path_prefixes=(),
                exclude_dirs_starting_with_digit=False,
            ),
        )

    def _write(self, relative: str, content: str, mtime: int) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        os.utime(path, (mtime, mtime))
        return path

    def test_first_scan_creates_baseline_without_events(self) -> None:
        self._write("sample.txt", "alpha", 1_700_000_001)

        result = scan_files(self._settings(hash_new_files=True))

        self.assertEqual(result["stats"]["scanned_files"], 1)
        self.assertEqual(result["stats"]["hashed_files"], 1)
        self.assertEqual(result["events"], [])
        events_csv = Path(result["reports"]["events_csv"])
        self.assertTrue(events_csv.exists())
        self.assertEqual(events_csv.parent.name, "events")

    def test_legacy_main_report_event_csvs_are_moved_to_events_folder(self) -> None:
        legacy = self.outdir / "events_legacy.csv"
        self.outdir.mkdir(parents=True)
        legacy.write_text("old report", encoding="utf-8")
        self._write("sample.txt", "alpha", 1_700_000_001)

        result = scan_files(self._settings(hash_new_files=True))

        self.assertFalse(legacy.exists())
        self.assertTrue((self.outdir / "events" / "events_legacy.csv").exists())
        self.assertEqual(Path(result["reports"]["events_csv"]).parent, self.outdir / "events")

    def test_changed_file_is_medium_severity(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=True))

        file_path.write_text("bravo", encoding="utf-8")
        os.utime(file_path, (1_700_000_002, 1_700_000_002))
        result = scan_files(self._settings(hash_new_files=True))

        self.assertEqual(result["stats"]["medium"], 1)
        self.assertEqual(result["events"][0]["type"], "changed")
        self.assertEqual(result["events"][0]["severity"], "medium")

    def test_reverted_file_is_critical_severity(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=True))

        file_path.write_text("bravo", encoding="utf-8")
        os.utime(file_path, (1_700_000_002, 1_700_000_002))
        changed = scan_files(self._settings(hash_new_files=True))
        self.assertEqual(changed["events"][0]["type"], "changed")

        file_path.write_text("alpha", encoding="utf-8")
        os.utime(file_path, (1_700_000_003, 1_700_000_003))
        reverted = scan_files(self._settings(hash_new_files=True))

        self.assertEqual(reverted["stats"]["critical"], 1)
        self.assertEqual(reverted["stats"]["high"], 0)
        self.assertEqual(reverted["events"][0]["type"], "reverted")
        self.assertEqual(reverted["events"][0]["severity"], "critical")
        assessment = reverted["events"][0]["details"]["assessment"]
        self.assertEqual(assessment["action_likelihood"], "Version reversion detected")
        self.assertEqual(assessment["risk"], "Extremely High")
        self.assertIn("extremely high risk", assessment["review_note"].lower())

    def test_history_deduplicates_same_fingerprint(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=True))

        os.utime(file_path, (1_700_000_002, 1_700_000_002))
        scan_files(self._settings(hash_new_files=True))

        connection = sqlite3.connect(self.db)
        try:
            count = connection.execute("SELECT COUNT(*) FROM history_by_path").fetchone()[0]
            seen_count = connection.execute("SELECT seen_count FROM history_by_path").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 1)
        self.assertEqual(seen_count, 2)

    def test_history_retention_caps_unique_fingerprints_per_path(self) -> None:
        settings = ScanSettings(
            root=self.root,
            db=self.db,
            outdir=self.outdir,
            max_workers=1,
            sample_bytes=4,
            hash_new_files=True,
            history_retention_per_path=2,
            exclusions=ExclusionConfig(
                dir_names=frozenset(),
                path_prefixes=(),
                exclude_dirs_starting_with_digit=False,
            ),
        )
        file_path = self._write("sample.txt", "v1", 1_700_000_001)
        scan_files(settings)
        for index, content in enumerate(("v2", "v3"), start=2):
            file_path.write_text(content, encoding="utf-8")
            os.utime(file_path, (1_700_000_000 + index, 1_700_000_000 + index))
            scan_files(settings)

        connection = sqlite3.connect(self.db)
        try:
            count = connection.execute("SELECT COUNT(*) FROM history_by_path").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 2)

    def test_no_hash_new_files_does_not_backfill_missing_fingerprint_on_second_observation(self) -> None:
        self._write("sample.txt", "alpha", 1_700_000_001)

        first = scan_files(self._settings(hash_new_files=False))
        second = scan_files(self._settings(hash_new_files=False))

        self.assertEqual(first["stats"]["hashed_files"], 0)
        self.assertEqual(first["stats"]["metadata_only_files"], 1)
        self.assertEqual(first["stats"]["reversion_unprotected_files"], 1)
        self.assertEqual(first["stats"]["skipped_missing_fingerprint_hashes"], 0)
        self.assertEqual(second["stats"]["hashed_files"], 0)
        self.assertEqual(second["stats"]["metadata_only_files"], 1)
        self.assertEqual(second["stats"]["reversion_unprotected_files"], 1)
        self.assertEqual(second["stats"]["skipped_missing_fingerprint_hashes"], 1)
        connection = sqlite3.connect(self.db)
        try:
            fingerprint, seen_count = connection.execute(
                "SELECT fingerprint, seen_count FROM latest_by_path"
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNone(fingerprint)
        self.assertEqual(seen_count, 2)

    def test_no_hash_new_files_reports_metadata_changed_for_fingerprintless_file(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        file_path.write_text("bravo", encoding="utf-8")
        os.utime(file_path, (1_700_000_002, 1_700_000_002))
        result = scan_files(self._settings(hash_new_files=False))

        self.assertEqual(result["stats"]["hashed_files"], 0)
        self.assertEqual(result["stats"]["metadata_only_files"], 1)
        self.assertEqual(result["stats"]["reversion_unprotected_files"], 1)
        self.assertEqual(result["stats"]["skipped_missing_fingerprint_hashes"], 1)
        self.assertEqual(result["stats"]["medium"], 1)
        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["type"], "metadata_changed")
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(assessment["action_likelihood"], "Metadata changed; content not fingerprinted")
        self.assertFalse(event["details"]["current_fingerprint_recorded"])

    def test_no_hash_new_files_reports_possible_metadata_reversion_on_size_and_mtime_match(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        file_path.write_text("changed-size", encoding="utf-8")
        os.utime(file_path, (1_700_000_002, 1_700_000_002))
        changed = scan_files(self._settings(hash_new_files=False))
        self.assertEqual(changed["events"][0]["type"], "metadata_changed")

        file_path.write_text("alpha", encoding="utf-8")
        os.utime(file_path, (1_700_000_001, 1_700_000_001))
        result = scan_files(self._settings(hash_new_files=False))

        self.assertEqual(result["stats"]["high"], 1)
        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["type"], "possible_metadata_reverted")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["details"]["metadata_match"], "size_mtime")
        self.assertEqual(assessment["action_likelihood"], "Possible version reversion from metadata history")
        self.assertEqual(assessment["action_confidence"], "medium")

    def test_existing_latest_state_seeds_metadata_history_for_possible_reversion(self) -> None:
        file_path = self._write("sample.txt", "changed-size", 1_700_000_002)
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                """
                CREATE TABLE latest_by_path (
                    path TEXT PRIMARY KEY,
                    size INTEGER NOT NULL,
                    mtime_utc INTEGER NOT NULL,
                    fingerprint TEXT,
                    last_seen_run_id TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO latest_by_path(path, size, mtime_utc, fingerprint, last_seen_run_id)
                VALUES(?, ?, ?, NULL, ?)
                """,
                (str(file_path.resolve()).lower(), len("alpha"), 1_700_000_001, "legacy"),
            )
            connection.commit()
        finally:
            connection.close()

        first = scan_files(self._settings(hash_new_files=False))
        self.assertEqual(first["events"][0]["type"], "metadata_changed")

        file_path.write_text("alpha", encoding="utf-8")
        os.utime(file_path, (1_700_000_001, 1_700_000_001))
        result = scan_files(self._settings(hash_new_files=False))

        self.assertEqual(result["events"][0]["type"], "possible_metadata_reverted")
        self.assertEqual(result["events"][0]["details"]["metadata_match"], "size_mtime")

    def test_no_hash_new_files_reports_size_only_metadata_reversion_as_medium(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        file_path.write_text("changed-size", encoding="utf-8")
        os.utime(file_path, (1_700_000_002, 1_700_000_002))
        scan_files(self._settings(hash_new_files=False))

        file_path.write_text("bravo", encoding="utf-8")
        os.utime(file_path, (1_700_000_003, 1_700_000_003))
        result = scan_files(self._settings(hash_new_files=False))

        self.assertEqual(result["stats"]["medium"], 1)
        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["type"], "possible_metadata_reverted")
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["details"]["metadata_match"], "size_only")
        self.assertEqual(assessment["action_likelihood"], "Possible size-pattern reversion")
        self.assertEqual(assessment["action_confidence"], "low")

    def test_hash_new_files_reports_metadata_changed_and_records_current_fingerprint_when_backfilling_changed_file(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        file_path.write_text("bravo", encoding="utf-8")
        os.utime(file_path, (1_700_000_002, 1_700_000_002))
        result = scan_files(self._settings(hash_new_files=True))

        self.assertEqual(result["stats"]["hashed_files"], 1)
        self.assertEqual(result["stats"]["metadata_only_files"], 0)
        self.assertEqual(result["stats"]["reversion_unprotected_files"], 0)
        event = result["events"][0]
        self.assertEqual(event["type"], "metadata_changed")
        self.assertEqual(event["severity"], "medium")
        self.assertTrue(event["details"]["current_fingerprint_recorded"])

    def test_hash_new_files_can_backfill_missing_fingerprint_later(self) -> None:
        self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        result = scan_files(self._settings(hash_new_files=True))

        self.assertEqual(result["stats"]["hashed_files"], 1)
        self.assertEqual(result["stats"]["metadata_only_files"], 0)
        self.assertEqual(result["stats"]["reversion_unprotected_files"], 0)
        self.assertEqual(result["stats"]["skipped_missing_fingerprint_hashes"], 0)
        connection = sqlite3.connect(self.db)
        try:
            fingerprint, seen_count = connection.execute(
                "SELECT fingerprint, seen_count FROM latest_by_path"
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNotNone(fingerprint)
        self.assertEqual(seen_count, 2)

    def test_missing_file_is_high_severity(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        file_path.unlink()
        result = scan_files(self._settings(hash_new_files=False))

        self.assertEqual(result["stats"]["high"], 1)
        self.assertEqual(result["events"][0]["type"], "missing")
        assessment = result["events"][0]["details"]["assessment"]
        self.assertEqual(assessment["action_likelihood"], "Likely deleted or currently unavailable")
        self.assertEqual(assessment["intent_confidence"], "low")

    def test_missing_file_with_same_fingerprint_in_same_folder_is_likely_renamed(self) -> None:
        original = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=True))

        moved = self.root / "renamed.txt"
        original.rename(moved)
        os.utime(moved, (1_700_000_002, 1_700_000_002))
        result = scan_files(self._settings(hash_new_files=True))

        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["type"], "missing")
        self.assertEqual(event["severity"], "low")
        self.assertEqual(assessment["action_likelihood"], "Likely renamed")
        self.assertEqual(assessment["candidate_action"], "rename")
        self.assertEqual(assessment["risk"], "Low")
        self.assertEqual(assessment["action_confidence"], "high")
        self.assertEqual(event["new_path"], str(moved.resolve()).lower())

    def test_missing_file_with_same_fingerprint_in_different_folder_is_likely_moved(self) -> None:
        original = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=True))

        destination_dir = self.root / "new_folder"
        destination_dir.mkdir()
        moved = destination_dir / "sample.txt"
        original.rename(moved)
        os.utime(moved, (1_700_000_002, 1_700_000_002))
        result = scan_files(self._settings(hash_new_files=True))

        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["type"], "missing")
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(assessment["action_likelihood"], "Likely moved")
        self.assertEqual(assessment["candidate_action"], "move")
        self.assertEqual(assessment["risk"], "Medium")
        self.assertEqual(event["new_path"], str(moved.resolve()).lower())

    def test_missing_file_with_same_fingerprint_different_folder_and_name_is_likely_moved_and_renamed(self) -> None:
        original = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=True))

        destination_dir = self.root / "new_folder"
        destination_dir.mkdir()
        moved = destination_dir / "renamed.txt"
        original.rename(moved)
        os.utime(moved, (1_700_000_002, 1_700_000_002))
        result = scan_files(self._settings(hash_new_files=True))

        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(assessment["action_likelihood"], "Likely moved and renamed")
        self.assertEqual(assessment["candidate_action"], "move_and_rename")

    def test_metadata_match_in_different_folder_and_name_is_possible_moved_and_renamed(self) -> None:
        original = self._write("draft 2.md", "draft body", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        destination_dir = self.root / "new_folder"
        destination_dir.mkdir()
        moved = destination_dir / "draft-final.md"
        original.rename(moved)
        result = scan_files(self._settings(hash_new_files=False))

        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["new_path"], str(moved.resolve()).lower())
        self.assertEqual(assessment["action_likelihood"], "Possibly moved and renamed")
        self.assertEqual(assessment["candidate_match"], "metadata")
        self.assertEqual(assessment["candidate_action"], "move_and_rename")

    def test_same_folder_filename_cleanup_is_likely_rename_without_hashing_new_files(self) -> None:
        original = self._write("draft 2.md", "draft body", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        renamed = self.root / "draft2.md"
        original.rename(renamed)
        result = scan_files(self._settings(hash_new_files=False))

        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(result["stats"]["high"], 0)
        self.assertEqual(result["stats"]["medium"], 0)
        self.assertEqual(result["stats"]["low"], 1)
        self.assertEqual(event["type"], "missing")
        self.assertEqual(event["severity"], "low")
        self.assertEqual(event["old_path"], str(original.resolve()).lower())
        self.assertEqual(event["new_path"], str(renamed.resolve()).lower())
        self.assertEqual(assessment["action_likelihood"], "Likely renamed")
        self.assertEqual(assessment["candidate_match"], "filename_metadata")
        self.assertEqual(assessment["candidate_action"], "rename")

    def test_rename_detection_finds_current_candidate_even_after_prior_new_baseline(self) -> None:
        original = self._write("draft 2.md", "draft body", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        renamed = self.root / "draft2.md"
        original.rename(renamed)
        scan_files(self._settings(hash_new_files=False))

        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                """
                INSERT INTO latest_by_path(path, size, mtime_utc, fingerprint, last_seen_run_id)
                VALUES(?, ?, ?, NULL, ?)
                """,
                (str(original.resolve()).lower(), len("draft body"), 1_700_000_001, "manual"),
            )
            connection.commit()
        finally:
            connection.close()

        result = scan_files(self._settings(hash_new_files=False))
        event = result["events"][0]
        self.assertEqual(event["severity"], "low")
        self.assertEqual(event["new_path"], str(renamed.resolve()).lower())

    def test_missing_paths_are_removed_from_latest_state_after_reporting(self) -> None:
        file_path = self._write("sample.txt", "alpha", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        file_path.unlink()
        scan_files(self._settings(hash_new_files=False))

        connection = sqlite3.connect(self.db)
        try:
            remaining = connection.execute("SELECT COUNT(*) FROM latest_by_path").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(remaining, 0)

    def test_directory_level_missing_pattern_is_summarised(self) -> None:
        for index in range(3):
            self._write(f"folder/sample_{index}.txt", f"value-{index}", 1_700_000_001)
        scan_files(self._settings(hash_new_files=False))

        for path in (self.root / "folder").iterdir():
            path.unlink()
        (self.root / "folder").rmdir()
        result = scan_files(self._settings(hash_new_files=False))

        self.assertEqual(result["stats"]["high"], 4)
        self.assertEqual(result["events"][0]["type"], "directory_missing")
        self.assertEqual(result["events"][0]["details"]["assessment"]["target_kind"], "directory")
        self.assertEqual(result["directory_impacts"][0]["missing_files"], 3)

    def test_empty_directory_deletion_is_reported_directly(self) -> None:
        empty_dir = self.root / "empty_folder"
        empty_dir.mkdir()
        scan_files(self._settings(hash_new_files=False))

        empty_dir.rmdir()
        result = scan_files(self._settings(hash_new_files=False))

        self.assertEqual(result["stats"]["high"], 1)
        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["type"], "directory_missing")
        self.assertEqual(event["old_path"], str(empty_dir.resolve()).lower())
        self.assertEqual(assessment["target_kind"], "directory")
        self.assertEqual(assessment["action_likelihood"], "Likely directory deleted or currently unavailable")
        self.assertEqual(result["directory_impacts"][0]["path"], str(empty_dir.resolve()).lower())

    def test_directory_rename_is_reported_as_directory_review_item(self) -> None:
        folder = self.root / "drafts"
        folder.mkdir()
        scan_files(self._settings(hash_new_files=False))

        renamed = self.root / "review_drafts"
        folder.rename(renamed)
        result = scan_files(self._settings(hash_new_files=False))

        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["type"], "directory_missing")
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["new_path"], str(renamed.resolve()).lower())
        self.assertEqual(assessment["candidate_action"], "rename")
        self.assertEqual(assessment["action_likelihood"], "Possibly renamed")

    def test_directory_metadata_reversion_is_reported_on_mtime_and_child_count_match(self) -> None:
        folder = self.root / "tracked_folder"
        folder.mkdir()
        os.utime(folder, (1_700_000_001, 1_700_000_001))
        scan_files(self._settings(hash_new_files=False))

        os.utime(folder, (1_700_000_002, 1_700_000_002))
        changed = scan_files(self._settings(hash_new_files=False))
        self.assertEqual(changed["events"], [])

        os.utime(folder, (1_700_000_001, 1_700_000_001))
        result = scan_files(self._settings(hash_new_files=False))

        self.assertEqual(result["stats"]["high"], 1)
        event = result["events"][0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["type"], "possible_directory_metadata_reverted")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["details"]["metadata_match"], "mtime_child_counts")
        self.assertEqual(assessment["action_likelihood"], "Possible directory metadata reversion")
        self.assertEqual(assessment["target_kind"], "directory")

    def test_directory_shape_reversion_is_reported_as_medium(self) -> None:
        folder = self.root / "tracked_folder"
        folder.mkdir()
        os.utime(folder, (1_700_000_001, 1_700_000_001))
        scan_files(self._settings(hash_new_files=False))

        child = self._write("tracked_folder/temporary.txt", "temporary", 1_700_000_002)
        os.utime(folder, (1_700_000_002, 1_700_000_002))
        scan_files(self._settings(hash_new_files=False))

        child.unlink()
        os.utime(folder, (1_700_000_003, 1_700_000_003))
        result = scan_files(self._settings(hash_new_files=False))

        directory_events = [
            event
            for event in result["events"]
            if event["type"] == "possible_directory_metadata_reverted"
        ]
        self.assertEqual(len(directory_events), 1)
        event = directory_events[0]
        assessment = event["details"]["assessment"]
        self.assertEqual(event["severity"], "medium")
        self.assertEqual(event["details"]["metadata_match"], "child_counts")
        self.assertEqual(assessment["action_likelihood"], "Possible directory shape-pattern reversion")

    def test_excluded_numbered_directories_are_pruned(self) -> None:
        self._write("1_old/sample.txt", "alpha", 1_700_000_001)
        exclusions = ExclusionConfig(
            dir_names=frozenset(),
            path_prefixes=(),
            exclude_dirs_starting_with_digit=True,
        )

        result = scan_files(self._settings(exclusions=exclusions))

        self.assertEqual(result["stats"]["scanned_files"], 0)

    def test_exclusions_file_can_be_edited_by_non_coders(self) -> None:
        exclusions_file = self.base / "extra_exclusions.txt"
        exclusions_file.write_text(
            "\n".join(
                [
                    "# One directory name per line",
                    "DoNotScan",
                    "dir: AlsoSkip",
                    f"prefix: {self.root / 'WholeSubtree'}",
                ]
            ),
            encoding="utf-8",
        )
        dir_names, prefixes = load_exclusions_file(exclusions_file)

        self.assertEqual(dir_names, {"DoNotScan", "AlsoSkip"})
        self.assertEqual(prefixes, [str(self.root / "WholeSubtree")])

    def test_exclusions_file_prunes_matching_directory_names(self) -> None:
        exclusions_file = self.base / "extra_exclusions.txt"
        exclusions_file.write_text("DoNotScan\n", encoding="utf-8")
        self._write("DoNotScan/sample.txt", "alpha", 1_700_000_001)
        self._write("Keep/sample.txt", "bravo", 1_700_000_001)
        exclusions = ExclusionConfig.from_cli(
            clear_defaults=True,
            exclude_dirs=(),
            exclude_prefixes=(),
            exclude_files=(exclusions_file,),
            include_numbered_dirs=True,
        )

        result = scan_files(self._settings(exclusions=exclusions))

        self.assertEqual(result["stats"]["scanned_files"], 1)

    def test_latest_json_is_written_for_scan_command_behavior(self) -> None:
        latest = self.base / "latest.json"
        self._write("sample.txt", "alpha", 1_700_000_001)
        settings = ScanSettings(
            root=self.root,
            db=self.db,
            outdir=self.outdir,
            latest_json=latest,
            max_workers=1,
            hash_new_files=False,
            exclusions=ExclusionConfig(
                dir_names=frozenset(),
                path_prefixes=(),
                exclude_dirs_starting_with_digit=False,
            ),
        )

        result = scan_files(settings)

        saved = json.loads(latest.read_text(encoding="utf-8"))
        self.assertEqual(saved["run_id"], result["run_id"])

    def test_scan_supports_spaces_in_root_file_database_and_report_paths(self) -> None:
        spaced_root = self.base / "research data root"
        spaced_root.mkdir()
        file_path = spaced_root / "folder with spaces" / "draft report 2.md"
        file_path.parent.mkdir()
        file_path.write_text("content", encoding="utf-8")
        settings = ScanSettings(
            root=spaced_root,
            db=self.base / "state files" / "monitor state.sqlite3",
            outdir=self.base / "report output",
            max_workers=1,
            hash_new_files=False,
            exclusions=ExclusionConfig(
                dir_names=frozenset(),
                path_prefixes=(),
                exclude_dirs_starting_with_digit=False,
            ),
        )

        result = scan_files(settings)

        self.assertEqual(result["stats"]["scanned_files"], 1)
        self.assertEqual(result["root"], str(spaced_root.resolve()).lower())
        self.assertTrue(Path(result["db"]).exists())
        self.assertTrue(Path(result["reports"]["events_csv"]).exists())

    def test_scan_emits_counted_progress_phases(self) -> None:
        self._write("one.txt", "one", 1_700_000_001)
        self._write("two.txt", "two", 1_700_000_002)
        updates = []
        settings = replace(
            self._settings(hash_new_files=True),
            progress_callback=updates.append,
        )

        result = scan_files(settings)

        phases = {update.phase for update in updates}
        self.assertEqual(result["stats"]["scanned_files"], 2)
        self.assertTrue({"Scanning", "Hashing", "Comparing", "Saving", "Reporting"} <= phases)
        final_scan = [update for update in updates if update.phase == "Scanning"][-1]
        self.assertEqual(final_scan.current, 2)
        self.assertEqual(final_scan.total, 2)
        self.assertFalse(final_scan.estimated)

    def test_fingerprint_read_failure_is_clear_and_does_not_commit_run(self) -> None:
        self._write("sample.txt", "alpha", 1_700_000_001)

        with patch(
            "file_integrity_monitor.scanner.compute_fingerprint",
            side_effect=PermissionError("access denied"),
        ):
            with self.assertRaisesRegex(
                ScanError,
                "Fingerprinting failed.*sample.txt.*access denied",
            ):
                scan_files(self._settings(hash_new_files=True))

        connection = sqlite3.connect(self.db)
        try:
            run_count = connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            latest_count = connection.execute(
                "SELECT COUNT(*) FROM latest_by_path"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(run_count, 0)
        self.assertEqual(latest_count, 0)

    def test_file_path_cannot_be_used_as_scan_root(self) -> None:
        file_root = self.base / "not a directory.txt"
        file_root.write_text("not a tree", encoding="utf-8")
        settings = replace(self._settings(), root=file_root)

        with self.assertRaisesRegex(ScanError, "Root is not a directory"):
            scan_files(settings)


if __name__ == "__main__":
    unittest.main()

"""Tests for dashboard API endpoints."""
import pytest
import time
from dashboard.db import EventDB


class TestTimeseries:
    @pytest.fixture
    def db(self, tmp_path):
        return EventDB(str(tmp_path / "test.db"))

    def test_returns_correct_bucket_count(self, db):
        result = db.timeseries(hours=24, buckets=12)
        assert len(result["data"]) == 12

    def test_empty_db_returns_zero_buckets(self, db):
        result = db.timeseries(hours=1, buckets=6)
        assert all(b["total"] == 0 for b in result["data"])

    def test_events_land_in_correct_bucket(self, db):
        now = time.time()
        # Insert event 30 min ago
        db.insert({"timestamp": now - 1800, "layer": "sanitizer", "verdict": "modified"})
        result = db.timeseries(hours=1, buckets=2)
        # First bucket (60-30 min ago) should have the event
        assert result["data"][0]["total"] == 1
        assert result["data"][1]["total"] == 0

    def test_blocked_count_separate(self, db):
        now = time.time()
        db.insert({"timestamp": now - 60, "layer": "analysis_guard", "verdict": "blocked"})
        db.insert({"timestamp": now - 60, "layer": "sanitizer", "verdict": "passed"})
        result = db.timeseries(hours=1, buckets=1)
        assert result["data"][0]["total"] == 2
        assert result["data"][0]["blocked"] == 1

    def test_layer_filter(self, db):
        now = time.time()
        db.insert({"timestamp": now - 60, "layer": "sanitizer", "verdict": "modified"})
        db.insert({"timestamp": now - 60, "layer": "canary", "verdict": "passed"})
        result = db.timeseries(hours=1, buckets=1, layer="sanitizer")
        assert result["data"][0]["total"] == 1

    def test_returns_metadata(self, db):
        result = db.timeseries(hours=12, buckets=6, layer="sanitizer")
        assert result["hours"] == 12
        assert result["buckets"] == 6
        assert result["layer"] == "sanitizer"

    def test_modified_count_separate(self, db):
        now = time.time()
        db.insert({"timestamp": now - 60, "layer": "sanitizer", "verdict": "modified"})
        db.insert({"timestamp": now - 60, "layer": "sanitizer", "verdict": "passed"})
        result = db.timeseries(hours=1, buckets=1)
        assert result["data"][0]["modified"] == 1
        assert result["data"][0]["total"] == 2

    def test_bucket_timestamps_are_ascending(self, db):
        result = db.timeseries(hours=6, buckets=6)
        timestamps = [b["t"] for b in result["data"]]
        assert timestamps == sorted(timestamps)

    def test_default_params(self, db):
        result = db.timeseries()
        assert result["hours"] == 24
        assert result["buckets"] == 24
        assert result["layer"] is None
        assert len(result["data"]) == 24

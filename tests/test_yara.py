import json
import os
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from assemblyline.common.importing import load_module_by_path
from assemblyline_service_utilities.testing.helper import TestHelper
from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection

# Force manifest location
os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "yara_", "service_manifest.yml")

# Setup folder locations
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")
SAMPLES_FOLDER = os.path.join(os.path.dirname(__file__), "samples")

# Initialize test helper
service_class = load_module_by_path("yara_.yara_.Yara", os.path.join(os.path.dirname(__file__), ".."))
th = TestHelper(service_class, RESULTS_FOLDER, SAMPLES_FOLDER)


@pytest.mark.parametrize("sample", [])
def test_sample(sample):
    start_time = time.time()
    th.run_test_comparison(sample)
    print(f"Time elapsed for {sample}: {round(time.time() - start_time)}s")


# ---------------------------------------------------------------------------
# Helpers for building lightweight yara_x match mocks
# ---------------------------------------------------------------------------

def _make_match(patterns):
    """
    Build a minimal mock of a yara_x MatchingRule object.

    ``patterns`` is a list of ``(identifier, [(offset, length), ...])`` tuples.
    """
    pattern_mocks = []
    for identifier, hits in patterns:
        match_objs = [SimpleNamespace(offset=off, length=ln) for off, ln in hits]
        pattern_mocks.append(SimpleNamespace(identifier=identifier, matches=match_objs))
    return SimpleNamespace(patterns=pattern_mocks)


def _make_service():
    """Return a bare Yara instance without loading any rules."""
    svc = service_class.__new__(service_class)
    svc.log = MagicMock()
    return svc


# ---------------------------------------------------------------------------
# Unit tests for _add_string_match_data
# ---------------------------------------------------------------------------

class TestAddStringMatchData:
    def setup_method(self):
        self.svc = _make_service()

    def test_empty_patterns(self):
        match = _make_match([])
        result = self.svc._add_string_match_data(match, b"")
        assert result == {}

    def test_named_string_single_hit(self):
        file_data = b"Hello, world!"
        # Pattern $greeting matches at offset 0, length 5 ("Hello")
        match = _make_match([("$greeting", [(0, 5)])])
        result = self.svc._add_string_match_data(match, file_data)
        assert "$greeting" in result
        assert "'Hello'" in result["$greeting"]
        assert "0x0" in result["$greeting"]

    def test_named_string_multiple_hits_same_value(self):
        file_data = b"abcabc"
        # Pattern $s matches "abc" at offsets 0 and 3
        match = _make_match([("$s", [(0, 3), (3, 3)])])
        result = self.svc._add_string_match_data(match, file_data)
        assert "$s" in result
        assert "(2x)" in result["$s"]

    def test_named_string_multiple_distinct_values(self):
        # "ab" at offset 0, "cd" at offset 2 – same pattern identifier but different content
        file_data = b"abcd"
        match = _make_match([("$s", [(0, 2), (2, 2)])])
        result = self.svc._add_string_match_data(match, file_data)
        # Because the two hits yield different byte sequences the entries are indexed
        assert "$s[0]" in result or "$s" in result

    def test_anonymous_string_key(self):
        file_data = b"test"
        match = _make_match([("$", [(0, 4)])])
        result = self.svc._add_string_match_data(match, file_data)
        assert "(anonymous)" in result

    def test_returns_dict_not_list(self):
        file_data = b"data"
        match = _make_match([("$x", [(0, 4)])])
        result = self.svc._add_string_match_data(match, file_data)
        assert isinstance(result, dict)

    def test_no_file_data(self):
        # When file_data is empty the matched_data will always be b""
        match = _make_match([("$s", [(0, 5)])])
        result = self.svc._add_string_match_data(match, b"")
        assert isinstance(result, dict)

    def test_long_value_truncated(self):
        file_data = b"A" * 200
        match = _make_match([("$long", [(0, 200)])])
        result = self.svc._add_string_match_data(match, file_data)
        assert "$long" in result
        assert len(result["$long"]) < 300  # truncated

    def test_string_matches_subsection_added(self):
        """_add_resultinfo_for_match should add a KEY_VALUE subsection for string matches."""
        file_data = b"Hello, world!"

        # Build a minimal match mock with metadata that the rest of the code expects
        mock_match = _make_match([("$greeting", [(0, 5)])])
        mock_match.namespace = "test_ns"
        mock_match.identifier = "test_rule"
        mock_match.tags = []

        # Stub out the parts of the service that aren't needed for this test
        svc = _make_service()
        svc.signatures_meta = {
            "test_ns.test_rule": {"classification": "TLP:CLEAR", "status": "DEPLOYED"}
        }
        svc.name = "yara"
        svc.ontology = MagicMock()

        from assemblyline_v4_service.common.result import Result
        from unittest.mock import patch

        # Patch YaraMetadata so we can control the metadata returned
        meta = MagicMock()
        meta.id = "test_rule"
        meta.mitre_att = None
        meta.al_score = None
        meta.category = "info"
        meta.actor_type = None
        meta.tags = []
        meta.malwares = []
        meta.actors = []
        meta.exploits = []
        meta.techniques = []
        meta.infos = []
        meta.behavior = set()
        meta.name = "test_rule"
        meta.classification = "TLP:CLEAR"

        with patch("yara_.yara_.YaraMetadata", return_value=meta):
            request = MagicMock()
            request.sha256 = "a" * 64
            request.deep_scan = False

            result = Result()
            svc._add_resultinfo_for_match(request, result, mock_match, file_data)

        assert len(result.sections) == 1
        section = result.sections[0]
        # There should be exactly one subsection: "String Matches"
        assert len(section.subsections) == 1
        string_section = section.subsections[0]
        assert string_section.title_text == "String Matches"
        assert string_section.body_format == BODY_FORMAT.KEY_VALUE
        body = json.loads(string_section.body)
        assert "$greeting" in body
        assert "'Hello'" in body["$greeting"]

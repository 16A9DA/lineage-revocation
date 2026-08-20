from unittest.mock import MagicMock, patch

from experiments.runners.collect import TimedWebSearchTool

# A benign research prompt returned CSAM-adjacent results with no safe-search
# param set (real incident). These tests only assert the outgoing request
# params, no network call is made.


def _tool():
    tool = TimedWebSearchTool.__new__(TimedWebSearchTool)
    tool.max_results = 5
    return tool


def _fake_response(text: str) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.raise_for_status = MagicMock()
    return resp


def test_bing_search_requests_strict_safe_search():
    tool = _tool()
    with patch("experiments.runners.collect.requests.get") as mock_get:
        mock_get.return_value = _fake_response("<rss><channel></channel></rss>")
        tool.search_bing("test query")
    params = mock_get.call_args.kwargs["params"]
    assert params["adlt"] == "strict"


def test_duckduckgo_search_requests_strict_safe_search():
    tool = _tool()
    with patch("experiments.runners.collect.requests.get") as mock_get, \
         patch.object(TimedWebSearchTool, "_create_duckduckgo_parser") as mock_parser:
        mock_get.return_value = _fake_response("")
        mock_parser.return_value.results = []
        tool.search_duckduckgo("test query")
    params = mock_get.call_args.kwargs["params"]
    assert params["kp"] == "1"

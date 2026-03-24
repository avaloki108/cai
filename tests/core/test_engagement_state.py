from cai.core.engagement_state import EngagementState


def test_engagement_state_tracks_targets_and_payloads() -> None:
    state = EngagementState(run_id="run-1")
    state.add_target("https://example.com")
    state.add_endpoint("/api/profile")
    state.record_payload_attempt("ssrf_probe", "https://example.com/fetch", "http://127.0.0.1")
    state.register_callback_token("tok1")
    state.add_callback_event("tok1", "dns", "resolver", "lookup")
    state.link_finding("finding-1", "evidence-1")

    snap = state.snapshot()
    assert snap["run_id"] == "run-1"
    assert "https://example.com" in snap["targets"]
    assert "/api/profile" in snap["discovered_endpoints"]
    assert snap["payload_attempts"][0]["module"] == "ssrf_probe"
    assert snap["callback_events"][0]["token"] == "tok1"
    assert snap["finding_links"]["finding-1"] == ["evidence-1"]

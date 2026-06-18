import json
import threading

from sentinel.config import SentinelConfig
from sentinel.output import write_evidence
from sentinel.schema import utc_now_iso


def _payload(control_id: str):
    return {
        "control_id": control_id,
        "collection_timestamp": utc_now_iso(),
        "status": "green",
        "collection_quality": "complete",
        "metrics": {},
        "evidence_artifacts": [],
        "findings": [],
        "errors": [],
        "notes": "concurrent",
        "provider": "mock",
    }


def test_concurrent_writes_do_not_corrupt(tmp_path):
    errors: list[str] = []

    def worker(cid: str):
        try:
            write_evidence(
                _payload(cid),
                base=tmp_path,
                extra_files={"data.json": json.dumps({"id": cid})},
                config=SentinelConfig(),
            )
        except Exception as exc:
            errors.append(str(exc))

    control_ids = ["CC6.1", "CC6.2", "CC7.1"]
    threads = [threading.Thread(target=worker, args=(cid,)) for cid in control_ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
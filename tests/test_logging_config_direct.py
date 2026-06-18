from sentinel.logging_config import configure_logging


def test_configure_logging_verbose_and_file(tmp_path):
    log_path = tmp_path / "sentinel.log"
    logger = configure_logging(verbose=True, log_file=log_path)
    logger.info("test message", extra={"collector": "iam_access_review"})
    assert log_path.exists()
    assert "test message" in log_path.read_text(encoding="utf-8")
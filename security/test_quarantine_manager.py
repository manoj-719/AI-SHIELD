from pathlib import Path

from security.quarantine_manager import (
    quarantine_file,
    release_quarantined_file,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_DIR = PROJECT_ROOT / "test_data"


def test_file_can_be_quarantined_and_released():

    file_path = TEST_DIR / "pytest_quarantine_test.txt"
    file_path.write_text(
        "Synthetic confidential test data",
        encoding="utf-8"
    )

    # Quarantine the file
    record = quarantine_file(
        file_path,
        "Automated quarantine test"
    )

    assert record["status"] == "quarantined"
    assert not file_path.exists()

    # Release the quarantined file
    result = release_quarantined_file(
        record["quarantine_id"]
    )

    restored_path = Path(result["restored_path"])

    assert result["success"] is True
    assert restored_path.exists()
    assert restored_path.read_text(encoding="utf-8") == (
        "Synthetic confidential test data"
    )
    assert result["record"]["status"] == "released"

    # Clean up test file
    restored_path.unlink()
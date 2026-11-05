
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
QUARANTINE_DIR = PROJECT_ROOT / "quarantine"
METADATA_FILE = QUARANTINE_DIR / "quarantine_log.json"

QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def quarantine_file(file_path, reason):

    source = Path(file_path).resolve()

    # Only allow files inside the project test-data directory.
    allowed_directory = (PROJECT_ROOT / "test_data").resolve()

    if not source.is_relative_to(allowed_directory):
        raise ValueError("Only test_data files can be quarantined")

    if not source.is_file():
        raise FileNotFoundError("File does not exist")

    if source == METADATA_FILE.resolve():
        raise ValueError("Invalid quarantine source")

    quarantine_id = f"QTN-{uuid.uuid4().hex[:10]}"
    destination = QUARANTINE_DIR / f"{quarantine_id}_{source.name}"

    shutil.move(str(source), str(destination))

    record = {
        "quarantine_id": quarantine_id,
        "original_name": source.name,
        "stored_name": destination.name,
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "quarantined"
    }

    records = []

    if METADATA_FILE.exists():
        records = json.loads(METADATA_FILE.read_text(encoding="utf-8"))

    records.append(record)

    METADATA_FILE.write_text(
        json.dumps(records, indent=4),
        encoding="utf-8"
    )

    return record
def release_quarantined_file(quarantine_id):
    records = []

    if METADATA_FILE.exists():
        records = json.loads(
            METADATA_FILE.read_text(encoding="utf-8")
        )

    record = next(
        (
            item for item in records
            if item["quarantine_id"] == quarantine_id
            and item["status"] == "quarantined"
        ),
        None
    )

    if record is None:
        raise ValueError("Active quarantine record not found")

    stored_path = QUARANTINE_DIR / record["stored_name"]
    restore_dir = PROJECT_ROOT / "test_data"
    restore_path = restore_dir / record["original_name"]

    if not stored_path.is_file():
        raise FileNotFoundError("Quarantined file not found")

    if restore_path.exists():
        raise FileExistsError("A file with the original name already exists")

    shutil.move(str(stored_path), str(restore_path))

    record["status"] = "released"
    record["released_at"] = datetime.now(timezone.utc).isoformat()

    METADATA_FILE.write_text(
        json.dumps(records, indent=4),
        encoding="utf-8"
    )

    return {
        "success": True,
        "message": "File released successfully",
        "restored_path": str(restore_path),
        "record": record
    }
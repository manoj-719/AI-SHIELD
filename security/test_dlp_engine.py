from security.dlp_engine import evaluate_file_transfer


def test_sensitive_file_is_quarantined():
    file_path = "test_data/pytest_dlp_test.txt"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("Customer email: customer@example.com")

    result = evaluate_file_transfer(
        file_path,
        "personal_email"
    )

    assert result["allowed"] is False
    assert result["status"] == "quarantined"
    assert "quarantine" in result


def test_public_file_transfer_is_allowed():
    file_path = "test_data/pytest_public_dlp.txt"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("Welcome to our public company website.")

    result = evaluate_file_transfer(
        file_path,
        "personal_email"
    )

    assert result["allowed"] is True
    assert result["status"] == "allowed"
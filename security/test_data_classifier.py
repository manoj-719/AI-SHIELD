from security.data_classifier import scan_file


def test_detects_sensitive_email():
    file_path = "test_data/pytest_email_test.txt"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("Contact: testuser@example.com")

    result = scan_file(file_path)

    assert result["is_sensitive"] is True
    assert result["findings"]["email"] == 1


def test_detects_sensitive_phone():
    file_path = "test_data/pytest_phone_test.txt"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("Phone: 9876543210")

    result = scan_file(file_path)

    assert result["is_sensitive"] is True
    assert result["findings"]["indian_phone"] == 1


def test_public_file_is_not_sensitive():
    file_path = "test_data/pytest_public_test.txt"

    with open(file_path, "w", encoding="utf-8") as file:
        file.write("Welcome to our company website.")

    result = scan_file(file_path)

    assert result["is_sensitive"] is False
    assert result["total_findings"] == 0
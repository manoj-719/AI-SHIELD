from flask import jsonify

def api_response(data=None, message=None, status_code=200, meta=None):
    """
    Generate a standardized JSON API response.
    """
    payload = {
        "success": True,
        "data": data
    }
    if message is not None:
        payload["message"] = message
    if meta is not None:
        payload["meta"] = meta
    return jsonify(payload), status_code

def error_response(message="An error occurred", status_code=400, details=None):
    """
    Generate a standardized error JSON response.
    """
    payload = {
        "success": False,
        "error": message
    }
    if details is not None:
        payload["details"] = details
    return jsonify(payload), status_code

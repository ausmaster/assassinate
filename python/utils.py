from __future__ import annotations
from json import loads


def validate_json(json_string: str) -> dict:
    """
    Validate and parse a JSON string.

    :param json_string: JSON string to parse.
    :return: Parsed JSON dictionary.
    """
    try:
        return loads(json_string)
    except ValueError:
        raise ValueError("Invalid JSON format.")

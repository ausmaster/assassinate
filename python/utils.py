from __future__ import annotations
import json
from typing import Any


def validate_json_structure(data: Any, schema: dict) -> bool:
    """
    Validate a JSON structure against a schema.

    This function checks if the given JSON-like object matches the expected schema.

    :param data: The JSON-like object to validate.
    :type data: Any
    :param schema: The schema to validate against.
    :type schema: dict

    :return: True if the data matches the schema, False otherwise.
    :rtype: bool

    :raises ValidationError: If the data does not match the schema.

    :Example:

        >>> from utils import validate_json_structure
        >>> data = {"key": "value"}
        >>> schema = {"key": str}
        >>> validate_json_structure(data, schema)
        True

    .. seealso:: :class:`exceptions.ValidationError`
    """
    if not isinstance(data, dict) or not isinstance(schema, dict):
        raise ValueError("Both data and schema must be dictionaries.")

    for key, value_type in schema.items():
        if key not in data:
            return False
        if not isinstance(data[key], value_type):
            return False
    return True


def load_json(file_path: str) -> dict:
    """
    Load JSON data from a file.

    :param file_path: Path to the JSON file.
    :type file_path: str

    :return: JSON data as a dictionary.
    :rtype: dict

    :raises FileNotFoundError: If the file does not exist.
    :raises json.JSONDecodeError: If the file contains invalid JSON.

    :Example:

        >>> from utils import load_json
        >>> config = load_json("config.json")
        >>> print(config)

    .. seealso:: :func:`save_json`
    """
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(data: dict, file_path: str) -> None:
    """
    Save a dictionary as a JSON file.

    :param data: The data to save.
    :type data: dict
    :param file_path: Path to save the JSON file.
    :type file_path: str

    :raises IOError: If the file cannot be written.

    :Example:

        >>> from utils import save_json
        >>> data = {"key": "value"}
        >>> save_json(data, "output.json")

    .. seealso:: :func:`load_json`
    """
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def deep_merge_dicts(base: dict, updates: dict) -> dict:
    """
    Recursively merge two dictionaries.

    :param base: The base dictionary.
    :type base: dict
    :param updates: The dictionary with updates.
    :type updates: dict

    :return: A merged dictionary with updates applied.
    :rtype: dict

    :Example:

        >>> from utils import deep_merge_dicts
        >>> base = {"a": 1, "b": {"c": 2}}
        >>> updates = {"b": {"d": 3}}
        >>> result = deep_merge_dicts(base, updates)
        >>> print(result)
        {'a': 1, 'b': {'c': 2, 'd': 3}}

    .. note::
        Nested keys will be recursively merged, and non-dictionary keys will be overwritten.
    """
    for key, value in updates.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            base[key] = deep_merge_dicts(base[key], value)
        else:
            base[key] = value
    return base


def pretty_print_json(data: dict) -> None:
    """
    Print a dictionary in a human-readable JSON format.

    :param data: The dictionary to print.
    :type data: dict

    :Example:

        >>> from utils import pretty_print_json
        >>> data = {"key": "value"}
        >>> pretty_print_json(data)

    .. seealso:: :func:`load_json`, :func:`save_json`
    """
    print(json.dumps(data, indent=4, sort_keys=True))

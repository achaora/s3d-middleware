import json
from pathlib import Path

class SBOMFormatError(Exception):
    """Raised when the input JSON does not have the expected SBOM structure."""
    pass

def load_and_strip_sbom(input_file: str | Path) -> dict:
    """
    Load a JSON file, validate it has a top-level 'sbom' key,
    and return the inner object.

    :param input_file: Path to JSON input file.
    :return: Inner 'sbom' dictionary.
    :raises SBOMFormatError: If structure is invalid.
    """
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise SBOMFormatError("Root of JSON must be an object.")

    if list(data.keys()) != ["sbom"]:
        raise SBOMFormatError("Root JSON must contain exactly one key: 'sbom'.")

    if not isinstance(data["sbom"], dict):
        raise SBOMFormatError("'sbom' must map to an object.")

    return data["sbom"]
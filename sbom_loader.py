import json
from pathlib import Path

class SBOMFormatError(Exception):
    """Raised when the input JSON is not structured properly."""
    pass

class SBOMLoader:
    """
    Loads and validates an SBOM JSON file.
    If the file has a top-level 'sbom' key, it will be stripped automatically.
    If not, the data is returned as-is.
    """

    def __init__(self, input_file: str | Path):
        self.input_file = Path(input_file)
        self.data: dict | None = None

    def load(self) -> "SBOMLoader":
        """Load JSON from file and auto-strip 'sbom' if present."""
        with open(self.input_file, "r", encoding="utf-8") as f:
            self.data = json.load(f)

        if not isinstance(self.data, dict):
            raise SBOMFormatError("Root of JSON must be an object.")

        # Auto-strip if the file only contains "sbom"
        if list(self.data.keys()) == ["sbom"]:
            if not isinstance(self.data["sbom"], dict):
                raise SBOMFormatError("'sbom' must map to an object.")
            self.data = self.data["sbom"]

        return self

    def get_data(self) -> dict:
        """Return processed SBOM data."""
        if self.data is None:
            raise SBOMFormatError("No SBOM data available. Did you call load()?") 
        return self.data

    def save(self, output_file: str | Path) -> None:
        """Save the processed SBOM JSON to a file."""
        if self.data is None:
            raise SBOMFormatError("No SBOM data available. Did you call load()?") 
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
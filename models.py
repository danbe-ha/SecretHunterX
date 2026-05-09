from dataclasses import dataclass, field
from enum import Enum

class SourceType(str, Enum):
    CODE = "code"
    RESOURCE = "resource"
    MANIFEST = "manifest"

@dataclass
class RawFinding:
    file_path: str
    line_number: int
    matched_value: str
    context_lines: list[str]
    pattern_name: str
    category: str
    source_type: SourceType
    entropy: float = 0.0
    confidence: float = 0.0
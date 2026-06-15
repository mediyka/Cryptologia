import csv
import io
from typing import Any, Dict, Iterable, List, Optional

from .specifications import CSVFormatSpec


class CSVFormatHandler:
    """Описывает публичный класс CSVFormatHandler."""
    format_name = "csv"
    spec = CSVFormatSpec()
    fields = list(spec.fields)

    def serialize(
        self,
        entries: Iterable[Dict],
        include_fields: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """Описывает публичное действие serialize."""
        selected_fields = include_fields or self.fields
        self.spec.validate_header(selected_fields, require_required=False)
        output = io.StringIO(newline="")
        if metadata:
            output.write(self.spec.metadata_line(metadata))
            output.write("\n")
        writer = csv.DictWriter(output, fieldnames=selected_fields, extrasaction="ignore")
        writer.writeheader()

        for entry in entries:
            row = dict(entry)
            if isinstance(row.get("tags"), list):
                row["tags"] = ",".join(str(tag) for tag in row["tags"])
            writer.writerow({field: row.get(field, "") for field in selected_fields})

        return output.getvalue().encode("utf-8-sig")

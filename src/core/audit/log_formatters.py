import csv
import json
from io import StringIO
from datetime import datetime, timezone
from typing import Iterable, List, Dict, Any


class AuditLogFormatter:
    """Форматирование журнала аудита для экспорта Sprint 5."""

    @staticmethod
    def to_signed_json(
        rows: Iterable[Dict[str, Any]],
        public_key: str = "",
        metadata: Dict[str, Any] = None,
    ) -> str:
        """Описывает публичное действие to signed json."""
        entries = [AuditLogFormatter._signed_entry(row) for row in rows]
        return json.dumps(
            {
                "format": "cryptosafe-audit-signed-json-v1",
                "metadata": metadata or AuditLogFormatter._default_metadata(),
                "public_key": public_key,
                "entries": entries,
            },
            ensure_ascii=False,
            indent=2,
        )

    @staticmethod
    def to_csv(rows: Iterable[Dict[str, Any]], metadata: Dict[str, Any] = None) -> str:
        """Описывает публичное действие to csv."""
        output = StringIO()
        writer = csv.writer(output)
        metadata = metadata or AuditLogFormatter._default_metadata()
        writer.writerow(["format", "cryptosafe-audit-csv-v1"])
        writer.writerow(["exported_at", metadata.get("exported_at", "")])
        writer.writerow(["exporter", metadata.get("exporter", "")])
        writer.writerow(["range_start", metadata.get("range", {}).get("start", "")])
        writer.writerow(["range_end", metadata.get("range", {}).get("end", "")])
        writer.writerow([])
        writer.writerow([
            "sequence_number",
            "timestamp",
            "event_type",
            "severity",
            "user_id",
            "source",
            "entry_id",
            "entry_hash",
            "signature",
            "details",
        ])
        for row in rows:
            entry = AuditLogFormatter._decode_entry(row.get("entry_data"))
            writer.writerow(
                [
                    row.get("sequence_number"),
                    row.get("timestamp"),
                    row.get("event_type"),
                    entry.get("severity", ""),
                    entry.get("user_id", ""),
                    entry.get("source", ""),
                    row.get("entry_id") or entry.get("entry_id", ""),
                    row.get("entry_hash", ""),
                    row.get("signature", ""),
                    json.dumps(entry.get("details", {}), ensure_ascii=False, sort_keys=True),
                ]
            )
        return output.getvalue()

    @staticmethod
    def to_cef(rows: Iterable[Dict[str, Any]]) -> str:
        """Описывает публичное действие to cef."""
        lines = []
        for row in rows:
            entry = AuditLogFormatter._decode_entry(row.get("entry_data"))
            cef = entry.get("cef") or AuditLogFormatter._row_to_cef(row, entry)
            lines.append(cef)
        return "\n".join(lines) + ("\n" if lines else "")

    @staticmethod
    def to_pdf(rows: Iterable[Dict[str, Any]], metadata: Dict[str, Any] = None) -> bytes:
        """Описывает публичное действие to pdf."""
        metadata = metadata or AuditLogFormatter._default_metadata()
        rows = list(rows)
        lines = [
            "CryptoSafe Manager Audit Report",
            f"Exported at: {metadata.get('exported_at', '')}",
            f"Exporter: {metadata.get('exporter', '')}",
            f"Range: {metadata.get('range', {}).get('start') or 'begin'} - {metadata.get('range', {}).get('end') or 'end'}",
            f"Entries: {len(rows)}",
            "",
        ]

        frequencies = {}
        failed_logins = 0
        suspicious = 0
        for row in rows:
            event_type = row.get("event_type") or ""
            frequencies[event_type] = frequencies.get(event_type, 0) + 1
            if event_type in {"LoginFailed", "FailedAuthAttempt"}:
                failed_logins += 1
            if "Suspicious" in event_type or event_type in {"TamperDetected", "SecurityPolicyViolation"}:
                suspicious += 1

        lines.extend(
            [
                "Summary",
                f"Failed logins: {failed_logins}",
                f"Suspicious events: {suspicious}",
                "",
                "Event frequency",
            ]
        )
        for event_type, count in sorted(frequencies.items()):
            lines.append(f"{event_type or 'Unknown'}: {count}")

        lines.extend(["", "Recent entries"])
        for row in rows[:60]:
            entry = AuditLogFormatter._decode_entry(row.get("entry_data"))
            severity = entry.get("severity", "")
            lines.append(
                f"#{row.get('sequence_number')} {row.get('timestamp')} "
                f"{row.get('event_type')} {severity} hash={str(row.get('entry_hash') or '')[:12]}"
            )

        return AuditLogFormatter._simple_pdf(lines)

    @staticmethod
    def _signed_entry(row: Dict[str, Any]) -> Dict[str, Any]:
        entry_data = row.get("entry_data")
        if isinstance(entry_data, bytes):
            entry_data = entry_data.decode("utf-8")
        return {
            "sequence_number": row.get("sequence_number"),
            "previous_hash": row.get("previous_hash"),
            "entry_data": entry_data,
            "entry_hash": row.get("entry_hash"),
            "signature": row.get("signature"),
            "public_key": row.get("public_key"),
        }

    @staticmethod
    def _decode_entry(entry_data) -> Dict[str, Any]:
        if not entry_data:
            return {}
        try:
            raw = entry_data if isinstance(entry_data, bytes) else str(entry_data).encode("utf-8")
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _row_to_cef(row: Dict[str, Any], entry: Dict[str, Any]) -> str:
        severity_map = {"INFO": 3, "WARN": 6, "ERROR": 8, "CRITICAL": 10}
        event_type = AuditLogFormatter._escape_cef(str(row.get("event_type") or entry.get("event_type", "")))
        source = AuditLogFormatter._escape_cef(str(entry.get("source", "")))
        severity = severity_map.get(str(entry.get("severity", "INFO")).upper(), 3)
        extension = {
            "rt": row.get("timestamp") or entry.get("timestamp", ""),
            "suid": entry.get("user_id", ""),
            "cs1": row.get("entry_id") or entry.get("entry_id") or "",
            "cs1Label": "entryId",
            "cs2": row.get("sequence_number") or entry.get("sequence_number", ""),
            "cs2Label": "sequenceNumber",
        }
        extension_text = " ".join(
            f"{key}={AuditLogFormatter._escape_cef(str(value))}"
            for key, value in extension.items()
        )
        return f"CEF:0|CryptoSafe|Manager|5|{event_type}|{source}|{severity}|{extension_text}"

    @staticmethod
    def _escape_cef(value: str) -> str:
        return value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")

    @staticmethod
    def _default_metadata() -> Dict[str, Any]:
        return {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "exporter": "default_user",
            "range": {"start": None, "end": None},
        }

    @staticmethod
    def _simple_pdf(lines: List[str]) -> bytes:
        # Минимальный PDF без внешних зависимостей: достаточно для читаемого отчёта.
        escaped_lines = [AuditLogFormatter._escape_pdf_text(line[:110]) for line in lines]
        text_commands = ["BT", "/F1 10 Tf", "50 790 Td", "14 TL"]
        for index, line in enumerate(escaped_lines):
            if index:
                text_commands.append("T*")
            text_commands.append(f"({line}) Tj")
        text_commands.append("ET")
        stream = "\n".join(text_commands).encode("latin-1", errors="replace")

        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
        ]

        pdf = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for number, obj in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{number} 0 obj\n".encode("ascii"))
            pdf.extend(obj)
            pdf.extend(b"\nendobj\n")

        xref_offset = len(pdf)
        pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        pdf.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        pdf.extend(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
        )
        return bytes(pdf)

    @staticmethod
    def _escape_pdf_text(text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

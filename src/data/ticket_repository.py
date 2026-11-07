"""Fuente única SQLite para tickets, revisiones, importaciones y fallos reintentables."""
from datetime import datetime, timezone
from contextlib import closing, contextmanager
from collections.abc import Iterator
import json
from pathlib import Path
import sqlite3
from typing import Any

from src.triage.output.validation import validate_ticket

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class TicketRepository:
    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else PROJECT_ROOT / "tickets.sqlite3"
        if not self.db_path.is_absolute():
            self.db_path = PROJECT_ROOT / self.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        if db_path is None:
            self._recover_previous_database(PROJECT_ROOT / "data/tickets.sqlite3")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _init_db(self) -> None:
        with self._connect() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS tickets (
                id TEXT PRIMARY KEY, alert_id TEXT, status TEXT, created_at TEXT,
                details TEXT, trace TEXT, decision TEXT, note TEXT, review_timestamp TEXT
            )""")
            columns = {row["name"] for row in con.execute("PRAGMA table_info(tickets)")}
            for column in ("decision", "note", "review_timestamp"):
                if column not in columns:
                    con.execute(f"ALTER TABLE tickets ADD COLUMN {column} TEXT")
            if "review_decision" in columns:
                con.execute("""UPDATE tickets SET
                    decision = COALESCE(decision, review_decision),
                    note = COALESCE(note, review_note)""")
            con.execute("CREATE INDEX IF NOT EXISTS tickets_alert ON tickets(alert_id)")
            con.execute("""CREATE TABLE IF NOT EXISTS imported_alerts (
                alert_id TEXT PRIMARY KEY, payload TEXT NOT NULL, imported_at TEXT NOT NULL
            )""")
            con.execute("""CREATE TABLE IF NOT EXISTS triage_attempts (
                alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, stage TEXT,
                error TEXT, trace TEXT NOT NULL, updated_at TEXT NOT NULL
            )""")

    def _recover_previous_database(self, path: Path) -> None:
        """Copiar sin borrar ni reemplazar registros del antiguo almacén alternativo."""
        if not path.is_file() or path.resolve() == self.db_path.resolve():
            return
        with closing(sqlite3.connect(path)) as old:
            old.row_factory = sqlite3.Row
            if not old.execute("SELECT 1 FROM sqlite_master WHERE name='tickets'").fetchone():
                return
            with self._connect() as con:
                for row in old.execute("SELECT * FROM tickets"):
                    record = dict(row)
                    con.execute("""INSERT OR IGNORE INTO tickets
                        (id, alert_id, status, created_at, details, trace, decision, note, review_timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
                        record["id"], record.get("alert_id"), record.get("status"),
                        record.get("created_at"), record.get("details") or "{}",
                        record.get("trace") or "[]", record.get("decision") or record.get("review_decision"),
                        record.get("note") or record.get("review_note"), record.get("review_timestamp"),
                    ))

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["details"] = json.loads(result.get("details") or "{}")
        result["trace"] = json.loads(result.get("trace") or "[]")
        if not result["trace"]:
            result["trace"] = result["details"].get("trace", [])
        result["review"] = {
            "decision": result.get("decision"), "note": result.get("note"),
            "timestamp": result.get("review_timestamp"),
        }
        return result

    def save(self, ticket: dict, trace: list[dict], *, allow_reprocess: bool = False) -> None:
        payload = validate_ticket(ticket["details"]["ticket"])
        if payload.ticket_id != ticket["id"] or ticket["alert_id"] not in payload.alert_ids:
            raise ValueError("Los identificadores del registro no coinciden con el ticket.")
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            if not allow_reprocess:
                placeholders = ",".join("?" for _ in payload.alert_ids)
                duplicate = con.execute(f"""SELECT tickets.id FROM tickets,
                    json_each(details, '$.ticket.alert_ids') AS alerts
                    WHERE alerts.value IN ({placeholders}) LIMIT 1""", payload.alert_ids).fetchone()
                if duplicate:
                    raise ValueError(f"La alerta ya tiene el ticket {duplicate['id']}.")
            con.execute("""INSERT INTO tickets
                (id, alert_id, status, created_at, details, trace)
                VALUES (?, ?, ?, ?, ?, ?)""", (
                ticket["id"], ticket["alert_id"], "new", ticket.get("created_at") or utc_now(),
                json.dumps(ticket["details"], ensure_ascii=False), json.dumps(trace, ensure_ascii=False),
            ))

    def get(self, ticket_id: str) -> dict | None:
        with self._connect() as con:
            row = con.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        return self._record(row) if row else None

    def find_by_alert(self, alert_id: str) -> dict | None:
        with self._connect() as con:
            row = con.execute("""SELECT * FROM tickets WHERE EXISTS (
                SELECT 1 FROM json_each(details, '$.ticket.alert_ids') WHERE value = ?
                ) ORDER BY created_at DESC, rowid DESC LIMIT 1""", (alert_id,)).fetchone()
        return self._record(row) if row else None

    def processed_alert_ids(self) -> set[str]:
        with self._connect() as con:
            return {row[0] for row in con.execute("""SELECT DISTINCT alerts.value
                FROM tickets, json_each(details, '$.ticket.alert_ids') AS alerts""")}

    def list_recent(self, limit: int = 25, *, offset: int = 0, search: str = "",
                    verdict: str = "", severity: str = "", escalation: bool | None = None,
                    review: str = "", include_legacy: bool = False) -> list[dict]:
        conditions, params = [], []
        if not include_legacy:
            conditions.append("json_extract(details, '$.ticket.ticket_id') IS NOT NULL")
        if search:
            conditions.append("(id LIKE ? OR alert_id LIKE ? OR EXISTS (SELECT 1 FROM json_each(details, '$.ticket.alert_ids') WHERE value LIKE ?))")
            params.extend([f"%{search}%"] * 3)
        for key, value in (("verdict", verdict), ("severity", severity)):
            if value:
                conditions.append(f"json_extract(details, '$.ticket.{key}') = ?")
                params.append(value)
        if escalation is not None:
            conditions.append("json_extract(details, '$.ticket.escalation.escalate') = ?")
            params.append(int(escalation))
        if review:
            conditions.append("COALESCE(decision, '') = ?")
            params.append("" if review == "pending" else review)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self._connect() as con:
            rows = con.execute("SELECT * FROM tickets" + where +
                               " ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                               [*params, limit, offset]).fetchall()
        return [self._record(row) for row in rows]

    def stats(self) -> dict[str, int]:
        with self._connect() as con:
            row = con.execute("""SELECT COUNT(*) AS tickets,
                COALESCE(SUM(decision IS NULL), 0) AS pending_review,
                COALESCE(SUM(json_extract(details, '$.ticket.severity') IN ('high', 'critical')), 0) AS high_critical
                FROM tickets WHERE json_extract(details, '$.ticket.ticket_id') IS NOT NULL""").fetchone()
            legacy = con.execute("SELECT COUNT(*) FROM tickets WHERE json_extract(details, '$.ticket.ticket_id') IS NULL").fetchone()[0]
        return {**dict(row), "processed": len(self.processed_alert_ids()), "legacy": legacy}

    def save_review(self, ticket_id: str, decision: str, note: str) -> None:
        if decision not in {"close", "reject_close", "escalate", "continue_investigation"}:
            raise ValueError("Decisión de revisión no válida.")
        if not self.get(ticket_id):
            raise LookupError("Ticket no encontrado.")
        with self._connect() as con:
            con.execute("""UPDATE tickets SET decision = ?, note = ?, review_timestamp = ?,
                status = 'reviewed' WHERE id = ?""", (decision, note, utc_now(), ticket_id))

    def import_alert(self, alert: dict) -> bool:
        with self._connect() as con:
            cursor = con.execute("INSERT OR IGNORE INTO imported_alerts VALUES (?, ?, ?)",
                                 (alert["alert_id"], json.dumps(alert, ensure_ascii=False), utc_now()))
            return cursor.rowcount == 1

    def get_imported_alert(self, alert_id: str) -> dict | None:
        with self._connect() as con:
            row = con.execute("SELECT payload FROM imported_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_imported_alerts(self, *, status: str = "new", rule_id: str = "",
                             desde: str = "", hasta: str = "") -> list[dict]:
        with self._connect() as con:
            rows = con.execute("SELECT payload FROM imported_alerts ORDER BY imported_at, alert_id").fetchall()
        alerts = [json.loads(row[0]) for row in rows]
        return [a for a in alerts if (status == "all" or a["status"] == status)
                and (not rule_id or a["rule_id"] == rule_id)
                and (not desde or a["created_at"] >= desde)
                and (not hasta or a["created_at"] <= hasta)]

    def record_attempt(self, alert_id: str, status: str, stage: str,
                       trace: list[dict], error: str = "") -> None:
        with self._connect() as con:
            con.execute("""INSERT INTO triage_attempts VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status, stage=excluded.stage,
                error=excluded.error, trace=excluded.trace, updated_at=excluded.updated_at""",
                        (alert_id, status, stage, error, json.dumps(trace, ensure_ascii=False), utc_now()))

    def list_attempts(self, status: str = "failed") -> list[dict]:
        with self._connect() as con:
            return [dict(row) for row in con.execute(
                "SELECT * FROM triage_attempts WHERE status = ? ORDER BY updated_at DESC", (status,))]

    def close(self) -> None:
        # Las operaciones usan su propia conexión, sin compartirla entre sesiones UI.
        return None


SQLiteTicketRepository = TicketRepository

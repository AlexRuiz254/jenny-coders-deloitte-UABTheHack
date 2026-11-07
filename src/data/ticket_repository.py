import json
import datetime
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Union


class TicketRepository:
    """Repository that persists tickets and their investigation trace in SQLite."""

    def __init__(self, db_path: str = "tickets.sqlite3") -> None:
        """
        Initialise the repository.

        Parameters
        ----------
        db_path: str
            Relative path (default ``tickets.sqlite3``) or absolute path to the
            SQLite file.  If a relative path is supplied it is placed inside the
            project’s ``data`` folder (three levels up from this file).
        """
        if not Path(db_path).is_absolute():
            db_path = (
                Path(__file__).resolve().parents[2] / "data" / db_path
            )
        self.db_path = Path(db_path)

        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id TEXT PRIMARY KEY,
                    alert_id TEXT,
                    status TEXT,
                    created_at TEXT,
                    details TEXT,            -- JSON representation of the alert payload
                    trace TEXT,              -- JSON list of investigation steps
                    review_decision TEXT,
                    review_note TEXT,
                    review_timestamp TEXT
                );
                """
            )
            conn.commit()

    def save(self, ticket: Dict[str, Any], trace: List[Dict[str, Any]]) -> None:

        trace_json = json.dumps(trace, ensure_ascii=False)
        details_json = json.dumps(ticket.get("details", {}), ensure_ascii=False)

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO tickets
                (id, alert_id, status, created_at, details, trace)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (
                    ticket["id"],
                    ticket.get("alert_id", ""),
                    ticket.get("status", "new"),
                    ticket.get("created_at", ""),
                    details_json,
                    trace_json,
                ),
            )
            conn.commit()

    def get(self, ticket_id: str) -> Union[Dict[str, Any], None]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, alert_id, status, created_at, details, trace,
                       review_decision, review_note, review_timestamp
                FROM tickets
                WHERE id = ?;
                """,
                (ticket_id,),
            )
            row = cur.fetchone()
            if not row:
                return None

            (
                tid,
                aid,
                status,
                created_at,
                details_json,
                trace_json,
                review_decision,
                review_note,
                review_timestamp,
            ) = row

            return {
                "id": tid,
                "alert_id": aid,
                "status": status,
                "created_at": created_at,
                "details": json.loads(details_json) if details_json else {},
                "trace": json.loads(trace_json) if trace_json else [],
                "review": {
                    "decision": review_decision,
                    "note": review_note,
                    "timestamp": review_timestamp,
                },
            }

    def list_recent(self, limit: int = 25) -> List[Dict[str, Any]]:
        """Listar los últimos *limit* tickets (ordenados por ``created_at`` descendente)."""
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, alert_id, status, created_at, details
                FROM tickets
                ORDER BY created_at DESC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = cur.fetchall()
            result: List[Dict[str, Any]] = []
            for tid, aid, status, created_at, details_json in rows:
                result.append(
                    {
                        "id": tid,
                        "alert_id": aid,
                        "status": status,
                        "created_at": created_at,
                        "details": json.loads(details_json) if details_json else {},
                    }
                )
            return result

    def save_review(self, ticket_id: str, decision: str, note: str) -> None:
 
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE tickets
                SET review_decision = ?, review_note = ?, review_timestamp = ?
                WHERE id = ?;
                """,
                (decision, note, timestamp, ticket_id),
            )
            conn.commit()

SQLiteTicketRepository = TicketRepository

import json
import sqlite3
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class TicketRepository:
    """SQLite‑backed repository for tickets.

    The database schema consists of a single ``tickets`` table:

    CREATE TABLE IF NOT EXISTS tickets (
        id TEXT PRIMARY KEY,
        alert_id TEXT,
        status TEXT,
        created_at TEXT,
        details TEXT,      -- JSON representation of the Alert model
        trace TEXT,        -- JSON list of dicts
        decision TEXT,     -- human review decision (optional)
        note TEXT          -- optional note for the decision
    );
    """

    def __init__(self, db_path: Union[Path, str] = None) -> None:
        """
        Parameters
        ----------
        db_path : Path | str
            Location of the SQLite file.  If *None*, the file ``tickets.sqlite3``
            is created in the project root.
        """
        if db_path is None:
            db_path = Path(__file__).resolve().parents[2] / "tickets.sqlite3"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)

        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tickets (
                id TEXT PRIMARY KEY,
                alert_id TEXT,
                status TEXT,
                created_at TEXT,
                details TEXT,
                trace TEXT,
                decision TEXT,
                note TEXT
            );
            """
        )
        self._conn.commit()

    def save(self, ticket: Dict[str, Any], trace: List[Dict[str, Any]]) -> None:
        """Persist a ticket together with its investigation trace.

        If a ticket with the same ``id`` already exists the row is replaced.
        ``trace`` is stored as a JSON string.
        """
        sql = """
        INSERT OR REPLACE INTO tickets (
            id, alert_id, status, created_at, details, trace, decision, note
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        details_json = json.dumps(ticket.get("details", {}))
        trace_json = json.dumps(trace)

        params = (
            ticket.get("id"),
            ticket.get("alert_id"),
            ticket.get("status"),
            ticket.get("created_at"),
            details_json,
            trace_json,
            ticket.get("decision"),
            ticket.get("note"),
        )
        self._conn.execute(sql, params)
        self._conn.commit()

    def get(self, ticket_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a ticket by its identifier. Returns ``None`` if not found."""
        cur = self._conn.execute(
            """
            SELECT id, alert_id, status, created_at, details, trace, decision, note
            FROM tickets WHERE id = ?
            """,
            (ticket_id,),
        )
        row = cur.fetchone()
        if not row:
            return None

        (
            _id,
            alert_id,
            status,
            created_at,
            details_json,
            trace_json,
            decision,
            note,
        ) = row
        return {
            "id": _id,
            "alert_id": alert_id,
            "status": status,
            "created_at": created_at,
            "details": json.loads(details_json),
            "trace": json.loads(trace_json),
            "decision": decision,
            "note": note,
        }

    def list_recent(self, limit: int = 25) -> List[Dict[str, Any]]:
        """Return the most recent *limit* tickets ordered by creation time."""
        cur = self._conn.execute(
            """
            SELECT id, alert_id, status, created_at, details, trace, decision, note
            FROM tickets ORDER BY created_at DESC LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        result: List[Dict[str, Any]] = []
        for row in rows:
            (
                _id,
                alert_id,
                status,
                created_at,
                details_json,
                trace_json,
                decision,
                note,
            ) = row
            result.append(
                {
                    "id": _id,
                    "alert_id": alert_id,
                    "status": status,
                    "created_at": created_at,
                    "details": json.loads(details_json),
                    "trace": json.loads(trace_json),
                    "decision": decision,
                    "note": note,
                }
            )
        return result

    def save_review(self, ticket_id: str, decision: str, note: str) -> None:
        """Record a human review (decision + optional note) for a ticket."""
        self._conn.execute(
            "UPDATE tickets SET decision = ?, note = ? WHERE id = ?",
            (decision, note, ticket_id),
        )
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()


SQLiteTicketRepository = TicketRepository
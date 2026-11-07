import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Union


class SQLiteTicketRepository:
    def __init__(self, db_path: Union[Path, str] = None):
        if db_path is None:
            db_path = Path(__file__).resolve().parents[2] / "data" / "tickets.db"
        else:
            db_path = Path(db_path)

        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def add(self, ticket: Dict[str, Any]) -> None:
        """Insert a ticket into the DB."""
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO tickets (id, alert_id, status, created_at, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    ticket["id"],
                    ticket["alert_id"],
                    ticket["status"],
                    ticket["created_at"],
                    json.dumps(ticket["details"], ensure_ascii=False),
                ),
            )
            conn.commit()

    def all(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, alert_id, status, created_at, details FROM tickets"
            )
            rows = cur.fetchall()
            tickets = []
            for tid, aid, status, created, details_json in rows:
                tickets.append(
                    {
                        "id": tid,
                        "alert_id": aid,
                        "status": status,
                        "created_at": created,
                        "details": json.loads(details_json),
                    }
                )
            return tickets
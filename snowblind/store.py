"""A transaction protects the entire signer state, including cached responses."""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)")
            db.execute("INSERT OR IGNORE INTO state VALUES(1, '{}')")

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=30)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            state = json.loads(db.execute("SELECT value FROM state WHERE id=1").fetchone()[0])
            yield state
            db.execute("UPDATE state SET value=? WHERE id=1", (json.dumps(state),))
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def read(self):
        with sqlite3.connect(self.path) as db:
            return json.loads(db.execute("SELECT value FROM state WHERE id=1").fetchone()[0])

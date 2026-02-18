import os
import uuid
import queue
import threading
import hashlib
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from sqlalchemy import DateTime, String, create_engine, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    credential_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    user_handle: Mapped[str] = mapped_column(String(255), index=True)
    public_key: Mapped[str] = mapped_column(String(255))
    sign_count: Mapped[int] = mapped_column(default=0)


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    credential_id: Mapped[str] = mapped_column(String(255), index=True)
    challenge: Mapped[str] = mapped_column(String(255))
    assertion: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), index=True)
    rollback_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verification_attempts: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


def create_app() -> Flask:
    app = Flask(__name__)
    engine = create_engine(os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:postgres@db:5432/app"), future=True)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    q: queue.Queue[str] = queue.Queue()

    with SessionLocal() as db:
        existing = db.scalar(select(Credential).where(Credential.credential_id == 'cred-1'))
        if not existing:
            db.add(Credential(credential_id='cred-1', user_handle='user-1', public_key='pk-test-1'))
            db.commit()

    def expected_assertion(public_key: str, challenge: str) -> str:
        return hashlib.sha256(f"{public_key}:{challenge}".encode()).hexdigest()

    def verify_session(sid: str):
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid))
            if not row or row.status != 'pending':
                return
            row.verification_attempts += 1
            cred = db.scalar(select(Credential).where(Credential.credential_id == row.credential_id))
            if cred and row.assertion == expected_assertion(cred.public_key, row.challenge):
                row.status = 'active'
                cred.sign_count += 1
            else:
                row.status = 'rolled_back'
                row.rollback_reason = 'assertion_invalid'
            db.commit()

    def worker():
        while True:
            verify_session(q.get())
            q.task_done()

    threading.Thread(target=worker, daemon=True).start()

    @app.post('/auth/optimistic-login')
    def optimistic_login():
        data = request.get_json(force=True)
        row = SessionRecord(credential_id=data['credential_id'], challenge=data['challenge'], assertion=data['assertion'], status='pending')
        with SessionLocal() as db:
            db.add(row)
            db.commit()
            db.refresh(row)
        q.put(str(row.id))
        return jsonify({"session_id": str(row.id), "status": "pending", "optimistic": True}), 202

    @app.post('/auth/verify')
    def verify():
        sid = request.get_json(force=True)['session_id']
        verify_session(sid)
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid))
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"status": row.status, "attempts": row.verification_attempts, "rollback_reason": row.rollback_reason})

    @app.get('/auth/session')
    def session():
        sid = request.args.get('session_id', '')
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid)) if sid else None
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"session_id": sid, "status": row.status, "state_hint": "optimistic_biometric", "rollback": row.status == 'rolled_back'})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

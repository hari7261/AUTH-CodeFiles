import os
import uuid
import queue
import threading
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from sqlalchemy import Boolean, DateTime, String, create_engine, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class ProviderGrant(Base):
    __tablename__ = "provider_grants"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    auth_code: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(64))
    subject: Mapped[str] = mapped_column(String(255))
    used: Mapped[bool] = mapped_column(Boolean, default=False)


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(String(64))
    auth_code: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rollback_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verification_attempts: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


def create_app() -> Flask:
    app = Flask(__name__)
    engine = create_engine(os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:postgres@db:5432/app"), future=True)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    q: queue.Queue[str] = queue.Queue()

    def verify_session(sid: str):
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid))
            if not row or row.status != 'pending':
                return
            row.verification_attempts += 1
            grant = db.scalar(select(ProviderGrant).where(ProviderGrant.auth_code == row.auth_code, ProviderGrant.provider == row.provider))
            if grant and not grant.used:
                grant.used = True
                row.subject = grant.subject
                row.status = 'active'
            else:
                row.status = 'rolled_back'
                row.rollback_reason = 'oauth_exchange_failed'
            db.commit()

    def worker():
        while True:
            verify_session(q.get())
            q.task_done()

    threading.Thread(target=worker, daemon=True).start()

    @app.post('/provider/grant')
    def issue_grant():
        data = request.get_json(force=True)
        code = uuid.uuid4().hex
        with SessionLocal() as db:
            db.add(ProviderGrant(auth_code=code, provider=data.get('provider', 'github'), subject=data['subject']))
            db.commit()
        return jsonify({"auth_code": code, "provider": data.get('provider', 'github')})

    @app.post('/auth/optimistic-login')
    def optimistic_login():
        data = request.get_json(force=True)
        row = SessionRecord(provider=data.get('provider', 'github'), auth_code=data['auth_code'], status='pending')
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
            return jsonify({"status": row.status, "subject": row.subject, "attempts": row.verification_attempts, "rollback_reason": row.rollback_reason})

    @app.get('/auth/session')
    def session():
        sid = request.args.get('session_id', '')
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid)) if sid else None
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"session_id": sid, "status": row.status, "subject": row.subject, "reconciliation": "replace_identity" if row.status == 'active' else "rollback" if row.status == 'rolled_back' else "wait"})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

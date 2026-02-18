import os
import uuid
import queue
import threading
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
from sqlalchemy import Boolean, DateTime, ForeignKey, String, create_engine, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


class MagicLink(Base):
    __tablename__ = "magic_links"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), index=True)
    token: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), index=True)
    link_token: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    rollback_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
            if not row or row.status != "pending":
                return
            row.verification_attempts += 1
            link = db.scalar(select(MagicLink).where(MagicLink.token == row.link_token))
            now = datetime.now(timezone.utc)
            if link and not link.consumed and link.expires_at > now and link.email == row.email:
                link.consumed = True
                row.status = "active"
                row.verified_at = now
            else:
                row.status = "rolled_back"
                row.rollback_reason = "invalid_or_expired_link"
            db.commit()

    def worker():
        while True:
            verify_session(q.get())
            q.task_done()

    threading.Thread(target=worker, daemon=True).start()

    @app.post('/auth/link/create')
    def create_link():
        data = request.get_json(force=True)
        token = uuid.uuid4().hex
        with SessionLocal() as db:
            db.add(MagicLink(email=data['email'].lower(), token=token, expires_at=datetime.now(timezone.utc) + timedelta(minutes=15)))
            db.commit()
        return jsonify({"magic_link_token": token})

    @app.post('/auth/optimistic-login')
    def optimistic_login():
        data = request.get_json(force=True)
        row = SessionRecord(email=data['email'].lower(), link_token=data['magic_link_token'], status='pending')
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
            return jsonify({"session_id": sid, "status": row.status, "reason": row.rollback_reason, "attempts": row.verification_attempts})

    @app.get('/auth/session')
    def session():
        sid = request.args.get('session_id', '')
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid)) if sid else None
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"session_id": sid, "status": row.status, "client_patch": {"state": row.status, "rollback": row.status == 'rolled_back'}})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

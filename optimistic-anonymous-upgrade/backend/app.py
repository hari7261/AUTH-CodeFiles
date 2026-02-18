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


class AnonymousSession(Base):
    __tablename__ = "anonymous_sessions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cart_blob: Mapped[str] = mapped_column(String(2000), default='{}')


class UpgradeToken(Base):
    __tablename__ = "upgrade_tokens"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), index=True)
    token: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UpgradeAttempt(Base):
    __tablename__ = "upgrade_attempts"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    anonymous_session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey('anonymous_sessions.id'))
    email: Mapped[str] = mapped_column(String(255), index=True)
    token: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    rollback_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verification_attempts: Mapped[int] = mapped_column(default=0)
    anon: Mapped[AnonymousSession] = relationship()


def create_app() -> Flask:
    app = Flask(__name__)
    engine = create_engine(os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:postgres@db:5432/app"), future=True)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    q: queue.Queue[str] = queue.Queue()

    def verify_attempt(aid: str):
        with SessionLocal() as db:
            row = db.get(UpgradeAttempt, uuid.UUID(aid))
            if not row or row.status != 'pending':
                return
            row.verification_attempts += 1
            token = db.scalar(select(UpgradeToken).where(UpgradeToken.token == row.token, UpgradeToken.email == row.email))
            now = datetime.now(timezone.utc)
            if token and not token.used and token.expires_at > now:
                token.used = True
                row.status = 'active'
            else:
                row.status = 'rolled_back'
                row.rollback_reason = 'upgrade_token_invalid'
            db.commit()

    def worker():
        while True:
            verify_attempt(q.get())
            q.task_done()

    threading.Thread(target=worker, daemon=True).start()

    @app.post('/anon/create')
    def anon_create():
        data = request.get_json(force=True)
        with SessionLocal() as db:
            anon = AnonymousSession(cart_blob=data.get('cart_blob', '{"items":[]}'))
            db.add(anon)
            db.commit()
            db.refresh(anon)
        return jsonify({"anonymous_session_id": str(anon.id)})

    @app.post('/upgrade/token')
    def issue_token():
        data = request.get_json(force=True)
        t = uuid.uuid4().hex
        with SessionLocal() as db:
            db.add(UpgradeToken(email=data['email'].lower(), token=t, expires_at=datetime.now(timezone.utc) + timedelta(minutes=20)))
            db.commit()
        return jsonify({"upgrade_token": t})

    @app.post('/auth/optimistic-login')
    def optimistic_login():
        data = request.get_json(force=True)
        row = UpgradeAttempt(anonymous_session_id=uuid.UUID(data['anonymous_session_id']), email=data['email'].lower(), token=data['upgrade_token'], status='pending')
        with SessionLocal() as db:
            db.add(row)
            db.commit()
            db.refresh(row)
        q.put(str(row.id))
        return jsonify({"session_id": str(row.id), "status": 'pending', "optimistic": True}), 202

    @app.post('/auth/verify')
    def verify():
        sid = request.get_json(force=True)['session_id']
        verify_attempt(sid)
        with SessionLocal() as db:
            row = db.get(UpgradeAttempt, uuid.UUID(sid))
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"status": row.status, "rollback_reason": row.rollback_reason, "attempts": row.verification_attempts})

    @app.get('/auth/session')
    def session():
        sid = request.args.get('session_id', '')
        with SessionLocal() as db:
            row = db.get(UpgradeAttempt, uuid.UUID(sid)) if sid else None
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"session_id": sid, "status": row.status, "merge_action": "persist_anonymous_data" if row.status == 'active' else "restore_anonymous_only" if row.status == 'rolled_back' else "hold_dual_state"})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

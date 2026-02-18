import os
import uuid
import queue
import threading
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
from sqlalchemy import Boolean, DateTime, String, create_engine, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class DeviceChallenge(Base):
    __tablename__ = "device_challenges"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_code: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    user_code: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_code: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    rollback_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verification_attempts: Mapped[int] = mapped_column(default=0)


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
            challenge = db.scalar(select(DeviceChallenge).where(DeviceChallenge.device_code == row.device_code))
            now = datetime.now(timezone.utc)
            if challenge and challenge.approved:
                row.status = 'active'
            elif challenge and challenge.expires_at <= now:
                row.status = 'rolled_back'
                row.rollback_reason = 'device_code_expired'
            db.commit()

    def worker():
        while True:
            verify_session(q.get())
            q.task_done()

    threading.Thread(target=worker, daemon=True).start()

    @app.post('/device/start')
    def start_device():
        device_code = uuid.uuid4().hex
        user_code = uuid.uuid4().hex[:8].upper()
        with SessionLocal() as db:
            db.add(DeviceChallenge(device_code=device_code, user_code=user_code, expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)))
            db.commit()
        return jsonify({"device_code": device_code, "user_code": user_code})

    @app.post('/device/approve')
    def approve():
        data = request.get_json(force=True)
        with SessionLocal() as db:
            challenge = db.scalar(select(DeviceChallenge).where(DeviceChallenge.user_code == data['user_code']))
            if not challenge:
                return jsonify({"error": "not_found"}), 404
            challenge.approved = True
            db.commit()
        return jsonify({"approved": True})

    @app.post('/auth/optimistic-login')
    def optimistic_login():
        data = request.get_json(force=True)
        row = SessionRecord(device_code=data['device_code'], status='pending')
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
            return jsonify({"status": row.status, "rollback_reason": row.rollback_reason, "attempts": row.verification_attempts})

    @app.get('/auth/session')
    def session():
        sid = request.args.get('session_id', '')
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid)) if sid else None
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"session_id": sid, "status": row.status, "client_reconcile": "retry_poll" if row.status == 'pending' else "rollback" if row.status == 'rolled_back' else "commit"})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

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


class OtpChallenge(Base):
    __tablename__ = "otp_challenges"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    phone: Mapped[str] = mapped_column(String(32), index=True)
    otp_code: Mapped[str] = mapped_column(String(12))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    phone: Mapped[str] = mapped_column(String(32), index=True)
    challenge_id: Mapped[str] = mapped_column(String(255), index=True)
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
            challenge = db.get(OtpChallenge, uuid.UUID(row.challenge_id))
            now = datetime.now(timezone.utc)
            if challenge and challenge.verified:
                row.status = 'active'
            elif challenge and challenge.expires_at <= now:
                row.status = 'rolled_back'
                row.rollback_reason = 'otp_timeout'
            db.commit()

    def worker():
        while True:
            verify_session(q.get())
            q.task_done()

    threading.Thread(target=worker, daemon=True).start()

    @app.post('/otp/request')
    def request_otp():
        data = request.get_json(force=True)
        otp = data.get('otp_code', '123456')
        challenge = OtpChallenge(phone=data['phone'], otp_code=otp, expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
        with SessionLocal() as db:
            db.add(challenge)
            db.commit()
            db.refresh(challenge)
        return jsonify({"challenge_id": str(challenge.id), "otp_code_for_demo": otp})

    @app.post('/otp/submit')
    def submit_otp():
        data = request.get_json(force=True)
        with SessionLocal() as db:
            challenge = db.get(OtpChallenge, uuid.UUID(data['challenge_id']))
            if not challenge:
                return jsonify({"error": "not_found"}), 404
            if challenge.otp_code == data['otp_code'] and challenge.expires_at > datetime.now(timezone.utc):
                challenge.verified = True
                db.commit()
                return jsonify({"verified": True})
            return jsonify({"verified": False}), 400

    @app.post('/auth/optimistic-login')
    def optimistic_login():
        data = request.get_json(force=True)
        row = SessionRecord(phone=data['phone'], challenge_id=data['challenge_id'], status='pending')
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
            return jsonify({"session_id": sid, "status": row.status, "client_reconcile": {"rollback": row.status == 'rolled_back', "retry": row.status == 'pending'}})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

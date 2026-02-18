import os
import uuid
import queue
import threading
from datetime import datetime, timedelta, timezone

import jwt
from flask import Flask, jsonify, request
from sqlalchemy import Boolean, DateTime, ForeignKey, String, create_engine, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    rollback_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verification_nonce: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    verification_attempts: Mapped[int] = mapped_column(default=0)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    user: Mapped[User | None] = relationship()


def create_app() -> Flask:
    app = Flask(__name__)
    db_url = os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:postgres@db:5432/app")
    secret = os.getenv("JWT_SECRET", "change-me")
    engine = create_engine(db_url, future=True)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    work_q: queue.Queue[str] = queue.Queue()

    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == "engineer@example.com"))
        if not existing:
            db.add(User(email="engineer@example.com", password_hash="pass1234"))
            db.commit()

    def token_for(session_row: SessionRecord) -> str:
        payload = {"sid": str(session_row.id), "status": session_row.status, "exp": int(session_row.expires_at.timestamp())}
        return jwt.encode(payload, secret, algorithm="HS256")

    def verify_session(sid: str) -> None:
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid))
            if not row or row.status != "pending":
                return
            row.verification_attempts += 1
            user = db.scalar(select(User).where(User.email == row.email))
            if user and row.verification_nonce.endswith(user.password_hash[-4:]):
                row.user_id = user.id
                row.status = "active"
                row.verified_at = datetime.now(timezone.utc)
            else:
                row.status = "rolled_back"
                row.rollback_reason = "credentials_rejected"
            db.commit()

    def worker() -> None:
        while True:
            sid = work_q.get()
            verify_session(sid)
            work_q.task_done()

    threading.Thread(target=worker, daemon=True).start()

    @app.post('/auth/optimistic-login')
    def optimistic_login():
        data = request.get_json(force=True)
        email = data["email"].strip().lower()
        password = data["password"]
        nonce = f"{uuid.uuid4().hex}:{password[-4:]}"
        session_row = SessionRecord(email=email, status="pending", verification_nonce=nonce, expires_at=datetime.now(timezone.utc) + timedelta(minutes=20))
        with SessionLocal() as db:
            db.add(session_row)
            db.commit()
            db.refresh(session_row)
        work_q.put(str(session_row.id))
        return jsonify({"session_token": token_for(session_row), "session_id": str(session_row.id), "optimistic": True, "status": "pending"}), 202

    @app.post('/auth/verify')
    def verify():
        sid = request.get_json(force=True)["session_id"]
        verify_session(sid)
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid))
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"session_id": sid, "status": row.status, "rollback_reason": row.rollback_reason, "attempts": row.verification_attempts})

    @app.get('/auth/session')
    def get_session():
        sid = request.args.get("session_id", "")
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid)) if sid else None
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"session_id": sid, "status": row.status, "should_rollback": row.status == "rolled_back", "reconcile_action": "replace_local_session" if row.status != "pending" else "keep_optimistic"})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

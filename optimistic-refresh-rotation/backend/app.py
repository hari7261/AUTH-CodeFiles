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


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    family_id: Mapped[str] = mapped_column(String(255), index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RotationAttempt(Base):
    __tablename__ = "rotation_attempts"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    presented_token: Mapped[str] = mapped_column(String(255), index=True)
    speculative_access: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    rollback_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verification_attempts: Mapped[int] = mapped_column(default=0)


def create_app() -> Flask:
    app = Flask(__name__)
    engine = create_engine(os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:postgres@db:5432/app"), future=True)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    q: queue.Queue[str] = queue.Queue()

    with SessionLocal() as db:
        if not db.scalar(select(RefreshToken).where(RefreshToken.token == 'seed-refresh-token')):
            db.add(RefreshToken(token='seed-refresh-token', family_id='fam-1', expires_at=datetime.now(timezone.utc) + timedelta(days=7)))
            db.commit()

    def verify_attempt(aid: str):
        with SessionLocal() as db:
            row = db.get(RotationAttempt, uuid.UUID(aid))
            if not row or row.status != 'pending':
                return
            row.verification_attempts += 1
            token = db.scalar(select(RefreshToken).where(RefreshToken.token == row.presented_token))
            now = datetime.now(timezone.utc)
            if token and not token.revoked and not token.consumed and token.expires_at > now:
                token.consumed = True
                row.status = 'active'
            else:
                row.status = 'rolled_back'
                row.rollback_reason = 'refresh_rotation_invalid'
            db.commit()

    def worker():
        while True:
            verify_attempt(q.get())
            q.task_done()

    threading.Thread(target=worker, daemon=True).start()

    @app.post('/auth/optimistic-login')
    def optimistic_login():
        data = request.get_json(force=True)
        speculative = f"spec-{uuid.uuid4().hex}"
        row = RotationAttempt(presented_token=data['refresh_token'], speculative_access=speculative, status='pending')
        with SessionLocal() as db:
            db.add(row)
            db.commit()
            db.refresh(row)
        q.put(str(row.id))
        return jsonify({"session_id": str(row.id), "speculative_access_token": speculative, "status": 'pending', "optimistic": True}), 202

    @app.post('/auth/verify')
    def verify():
        sid = request.get_json(force=True)['session_id']
        verify_attempt(sid)
        with SessionLocal() as db:
            row = db.get(RotationAttempt, uuid.UUID(sid))
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"status": row.status, "rollback_reason": row.rollback_reason, "attempts": row.verification_attempts})

    @app.get('/auth/session')
    def session():
        sid = request.args.get('session_id', '')
        with SessionLocal() as db:
            row = db.get(RotationAttempt, uuid.UUID(sid)) if sid else None
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"session_id": sid, "status": row.status, "speculative_access_token": row.speculative_access, "must_revoke_client_access": row.status == 'rolled_back'})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

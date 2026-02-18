import os
import uuid
import queue
import threading
import hashlib
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
from sqlalchemy import Boolean, DateTime, String, create_engine, select
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class IdpAssertion(Base):
    __tablename__ = "idp_assertions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assertion_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    audience: Mapped[str] = mapped_column(String(255))
    signature: Mapped[str] = mapped_column(String(255))
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    assertion_id: Mapped[str] = mapped_column(String(255), index=True)
    audience: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), index=True)
    rollback_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verification_attempts: Mapped[int] = mapped_column(default=0)


def create_app() -> Flask:
    app = Flask(__name__)
    issuer_secret = os.getenv('IDP_SIGNING_SECRET', 'idp-secret')
    engine = create_engine(os.getenv("DATABASE_URL", "postgresql+psycopg2://postgres:postgres@db:5432/app"), future=True)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    q: queue.Queue[str] = queue.Queue()

    def sign(assertion_id: str, audience: str, email: str) -> str:
        return hashlib.sha256(f"{assertion_id}:{audience}:{email}:{issuer_secret}".encode()).hexdigest()

    def verify_session(sid: str):
        with SessionLocal() as db:
            row = db.get(SessionRecord, uuid.UUID(sid))
            if not row or row.status != 'pending':
                return
            row.verification_attempts += 1
            assertion = db.scalar(select(IdpAssertion).where(IdpAssertion.assertion_id == row.assertion_id))
            now = datetime.now(timezone.utc)
            if assertion and not assertion.consumed and assertion.expires_at > now and assertion.audience == row.audience and assertion.signature == sign(assertion.assertion_id, assertion.audience, assertion.email):
                assertion.consumed = True
                row.status = 'active'
            else:
                row.status = 'rolled_back'
                row.rollback_reason = 'sso_assertion_invalid'
            db.commit()

    def worker():
        while True:
            verify_session(q.get())
            q.task_done()

    threading.Thread(target=worker, daemon=True).start()

    @app.post('/idp/assertion')
    def create_assertion():
        data = request.get_json(force=True)
        assertion_id = uuid.uuid4().hex
        audience = data.get('audience', 'auth-demo-sp')
        email = data['email'].lower()
        signature = sign(assertion_id, audience, email)
        with SessionLocal() as db:
            db.add(IdpAssertion(assertion_id=assertion_id, email=email, audience=audience, signature=signature, expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)))
            db.commit()
        return jsonify({"assertion_id": assertion_id, "audience": audience, "signature": signature})

    @app.post('/auth/optimistic-login')
    def optimistic_login():
        data = request.get_json(force=True)
        row = SessionRecord(assertion_id=data['assertion_id'], audience=data.get('audience', 'auth-demo-sp'), status='pending')
        with SessionLocal() as db:
            db.add(row)
            db.commit()
            db.refresh(row)
        q.put(str(row.id))
        return jsonify({"session_id": str(row.id), "status": 'pending', "optimistic": True}), 202

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
            return jsonify({"session_id": sid, "status": row.status, "client_patch": "drop_local_sso_session" if row.status == 'rolled_back' else "continue_poll" if row.status == 'pending' else "commit_sso_identity"})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

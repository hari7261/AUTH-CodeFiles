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


class DeviceApproval(Base):
    __tablename__ = "device_approvals"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(String(255), index=True)
    new_device_id: Mapped[str] = mapped_column(String(255), index=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SyncSession(Base):
    __tablename__ = "sync_sessions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[str] = mapped_column(String(255), index=True)
    device_id: Mapped[str] = mapped_column(String(255), index=True)
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
            row = db.get(SyncSession, uuid.UUID(sid))
            if not row or row.status != 'pending':
                return
            row.verification_attempts += 1
            approval = db.scalar(select(DeviceApproval).where(DeviceApproval.user_id == row.user_id, DeviceApproval.new_device_id == row.device_id))
            now = datetime.now(timezone.utc)
            if approval and approval.approved:
                row.status = 'active'
            elif approval and approval.expires_at <= now:
                row.status = 'rolled_back'
                row.rollback_reason = 'approval_timeout'
            db.commit()

    def worker():
        while True:
            verify_session(q.get())
            q.task_done()

    threading.Thread(target=worker, daemon=True).start()

    @app.post('/device/challenge')
    def challenge():
        data = request.get_json(force=True)
        with SessionLocal() as db:
            approval = DeviceApproval(user_id=data['user_id'], new_device_id=data['device_id'], expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
            db.add(approval)
            db.commit()
            db.refresh(approval)
        return jsonify({"approval_id": str(approval.id)})

    @app.post('/device/approve')
    def approve():
        data = request.get_json(force=True)
        with SessionLocal() as db:
            approval = db.get(DeviceApproval, uuid.UUID(data['approval_id']))
            if not approval:
                return jsonify({"error": "not_found"}), 404
            approval.approved = True
            db.commit()
        return jsonify({"approved": True})

    @app.post('/auth/optimistic-login')
    def optimistic_login():
        data = request.get_json(force=True)
        row = SyncSession(user_id=data['user_id'], device_id=data['device_id'], status='pending')
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
            row = db.get(SyncSession, uuid.UUID(sid))
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"status": row.status, "attempts": row.verification_attempts, "rollback_reason": row.rollback_reason})

    @app.get('/auth/session')
    def session():
        sid = request.args.get('session_id', '')
        with SessionLocal() as db:
            row = db.get(SyncSession, uuid.UUID(sid)) if sid else None
            if not row:
                return jsonify({"error": "not_found"}), 404
            return jsonify({"session_id": sid, "status": row.status, "device_sync_action": "revoke_local_device" if row.status == 'rolled_back' else "wait_for_trusted_device" if row.status == 'pending' else "activate_sync"})

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

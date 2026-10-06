import json, mimetypes, os, uuid
from pathlib import Path
from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .config import settings
from .db import Base, engine, get_db
from .models import Analysis, User
from .schemas import RegisterRequest, LoginRequest, TokenResponse, AnalysisDetail, AnalysisSummary
from .security import hash_password, verify_password, create_token, current_user
from .analyzer import analyze_file
from .reports import build_report

Base.metadata.create_all(bind=engine)
Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)

app = FastAPI(title=settings.app_name, version="0.1.0", docs_url="/docs", redoc_url="/redoc")
origins = [x.strip() for x in settings.cors_origins.split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["GET","POST"], allow_headers=["Authorization","Content-Type"])

@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

@app.get("/health")
def health():
    return {"status": "ok", "service": settings.app_name}

@app.post("/api/v1/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    email = body.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "Account already exists")
    user = User(email=email, password_hash=hash_password(body.password))
    db.add(user); db.commit(); db.refresh(user)
    return TokenResponse(access_token=create_token(user.id))

@app.post("/api/v1/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid credentials")
    return TokenResponse(access_token=create_token(user.id))

async def save_upload(upload: UploadFile) -> tuple[Path, int]:
    max_bytes = settings.max_upload_mb * 1024 * 1024
    safe_name = Path(upload.filename or "unnamed").name
    suffix = Path(safe_name).suffix[:16]
    stored = f"{uuid.uuid4().hex}{suffix}"
    target = Path(settings.upload_dir) / stored
    total = 0
    with target.open("wb") as f:
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk: break
            total += len(chunk)
            if total > max_bytes:
                target.unlink(missing_ok=True)
                raise HTTPException(413, f"File too large. Max size is {settings.max_upload_mb} MB.")
            f.write(chunk)
    return target, total

@app.post("/api/v1/analyses", response_model=AnalysisSummary, status_code=201)
async def create_analysis(upload: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(current_user)):
    path, total = await save_upload(upload)
    try:
        result = analyze_file(path)
        row = Analysis(owner_id=user.id, original_name=Path(upload.filename or "unnamed").name, stored_name=path.name,
            size_bytes=total, status="completed", claimed_extension=result["claimed_extension"], claimed_mime=result["claimed_mime"],
            detected_type=result["detected_type"], detected_mime=result["detected_mime"], confidence=result["confidence"],
            md5=result["md5"], sha256=result["sha256"], sha512=result["sha512"], entropy=result["entropy"],
            risk_score=result["risk_score"], risk_level=result["risk_level"], findings_json=json.dumps(result["findings"]),
            indicators_json=json.dumps(result["indicators"]))
        db.add(row); db.commit(); db.refresh(row)
        return row
    except Exception:
        path.unlink(missing_ok=True)
        raise

@app.get("/api/v1/analyses", response_model=list[AnalysisSummary])
def list_analyses(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return db.scalars(select(Analysis).where(Analysis.owner_id == user.id).order_by(Analysis.created_at.desc()).limit(100)).all()

@app.get("/api/v1/analyses/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(analysis_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    row = db.scalar(select(Analysis).where(Analysis.id == analysis_id, Analysis.owner_id == user.id))
    if not row: raise HTTPException(404, "Analysis not found")
    payload = {
        "id": row.id,
        "original_name": row.original_name,
        "size_bytes": row.size_bytes,
        "status": row.status,
        "detected_type": row.detected_type,
        "detected_mime": row.detected_mime,
        "confidence": row.confidence,
        "claimed_extension": row.claimed_extension,
        "risk_score": row.risk_score,
        "risk_level": row.risk_level,
        "sha256": row.sha256,
        "entropy": row.entropy,
        "created_at": row.created_at,
        "claimed_mime": row.claimed_mime,
        "md5": row.md5,
        "sha512": row.sha512,
        "findings": json.loads(row.findings_json or "[]"),
        "indicators": json.loads(row.indicators_json or "{}"),
    }
    return payload

@app.get("/api/v1/analyses/{analysis_id}/report")
def report(analysis_id: int, db: Session = Depends(get_db), user: User = Depends(current_user)):
    row = db.scalar(select(Analysis).where(Analysis.id == analysis_id, Analysis.owner_id == user.id))
    if not row: raise HTTPException(404, "Analysis not found")
    pdf = build_report(row)
    return StreamingResponse(iter([pdf]), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="filesentry-{row.id}.pdf"'})

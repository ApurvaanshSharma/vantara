"""
Case management routes — create, list, detail, update, comment, close.
Full evidence chains/attachments (the original spec's fuller scope) are
out, same reasoning as everywhere else in this project.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.models.case import Case, CaseComment, CaseStatus
from app.models.user import User
from app.schemas.case import (
    CaseCommentCreate,
    CaseCommentOut,
    CaseCreate,
    CaseOut,
    CaseUpdate,
)

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])


def _get_case_or_404(db: Session, case_id) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Case not found"
        )
    return case


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Case:
    case = Case(
        title=payload.title,
        summary=payload.summary,
        severity=payload.severity,
        tags=payload.tags,
        alert_ids=payload.alert_ids,
        created_by_id=current_user.id,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


@router.get("", response_model=list[CaseOut])
def list_cases(
    status_filter: CaseStatus | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[Case]:
    query = db.query(Case)
    if status_filter is not None:
        query = query.filter(Case.status == status_filter)
    return query.order_by(Case.created_at.desc()).all()


@router.get("/{case_id}", response_model=CaseOut)
def get_case(
    case_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Case:
    return _get_case_or_404(db, case_id)


@router.patch("/{case_id}", response_model=CaseOut)
def update_case(
    case_id: str,
    payload: CaseUpdate,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Case:
    case = _get_case_or_404(db, case_id)
    if payload.status is not None:
        case.status = payload.status
        if payload.status == CaseStatus.CLOSED:
            case.closed_at = datetime.now(timezone.utc)
    if payload.assigned_to_id is not None:
        case.assigned_to_id = payload.assigned_to_id
    if payload.tags is not None:
        case.tags = payload.tags
    db.commit()
    db.refresh(case)
    return case


@router.post("/{case_id}/close", response_model=CaseOut)
def close_case(
    case_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Case:
    case = _get_case_or_404(db, case_id)
    case.status = CaseStatus.CLOSED
    case.closed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(case)
    return case


@router.post(
    "/{case_id}/comments",
    response_model=CaseCommentOut,
    status_code=status.HTTP_201_CREATED,
)
def add_comment(
    case_id: str,
    payload: CaseCommentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> CaseComment:
    _get_case_or_404(db, case_id)  # 404s before writing a comment to a nonexistent case
    comment = CaseComment(case_id=case_id, user_id=current_user.id, body=payload.body)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


@router.get("/{case_id}/comments", response_model=list[CaseCommentOut])
def list_comments(
    case_id: str,
    db: Session = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[CaseComment]:
    _get_case_or_404(db, case_id)
    return (
        db.query(CaseComment)
        .filter(CaseComment.case_id == case_id)
        .order_by(CaseComment.created_at.asc())
        .all()
    )

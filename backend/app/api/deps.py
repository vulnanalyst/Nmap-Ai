from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from backend.app.core.security import require_token
from backend.app.db.session import get_db

DbDep = Annotated[Session, Depends(get_db)]
AuthDep = Annotated[str, Depends(require_token)]

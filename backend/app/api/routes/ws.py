import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.app.core.config import get_settings
from backend.app.core.events import event_bus

router = APIRouter(tags=["ws"])


@router.websocket("/ws/events")
async def events(ws: WebSocket):
    token = ws.query_params.get("token")
    settings = get_settings()
    if token != settings.api_token:
        await ws.close(code=4401)
        return
    await ws.accept()
    try:
        async for event in event_bus.stream():
            await ws.send_text(json.dumps(event))
    except WebSocketDisconnect:
        return

import json
import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])
settings = get_settings()


@router.websocket("/ws/scan/{scan_job_id}")
async def scan_progress_ws(websocket: WebSocket, scan_job_id: str):
    """
    WebSocket endpoint that subscribes to the Redis pub/sub channel for a scan job
    and forwards progress events to the connected client.
    """
    await websocket.accept()
    channel_name = f"scan:{scan_job_id}:progress"

    redis_client = None
    pubsub = None

    try:
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(channel_name)

        # Send a connected confirmation
        await websocket.send_json(
            {"type": "connected", "scan_job_id": scan_job_id, "channel": channel_name}
        )

        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await websocket.send_json(data)
                    # Stop streaming once the scan completes or fails
                    if data.get("progress") == 100 or data.get("phase") in ("completed", "failed"):
                        break
                except (json.JSONDecodeError, ValueError):
                    continue

    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected for scan %s", scan_job_id)
    except Exception as exc:
        logger.error("WebSocket error for scan %s: %s", scan_job_id, exc)
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        if pubsub:
            try:
                await pubsub.unsubscribe(channel_name)
                await pubsub.close()
            except Exception:
                pass
        if redis_client:
            try:
                await redis_client.aclose()
            except Exception:
                pass

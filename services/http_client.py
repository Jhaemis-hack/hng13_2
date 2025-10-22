import httpx
from httpx import Timeout, Limits
from core.exceptions import ExternalServiceException


async def safe_http_request(
        method: str,
        url: str,
        *,
        json: dict | None = None,
        params: dict | None = None,
        headers: dict | None = None,
        timeout: int = 1.5
):
    try:
        async with httpx.AsyncClient(http2=True,
                                     timeout=Timeout(timeout),
                                     limits=Limits(max_keepalive_connections=10, max_connections=20)) as client:
            response = await client.request(
                method=method.upper(),
                url=url,
                json=json,
                params=params,
                headers=headers,
            )
            response.raise_for_status()
            return response.json()

    except httpx.RequestError as e:
        raise ExternalServiceException(f"Network error: {e}")

    except httpx.HTTPStatusError as e:
        raise ExternalServiceException(
            f"External service responded with {e.response.status_code}: {e.response.text}"
        )

from __future__ import annotations

import asyncio
from collections.abc import Mapping, MutableMapping
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

import httpx
from tenacity import AsyncRetrying, RetryError, retry_if_exception_type, stop_after_attempt, wait_exponential

from scanner.core.config import HttpSettings


class HttpClient:
    def __init__(
        self,
        settings: HttpSettings,
        default_headers: Optional[Mapping[str, str]] = None,
        rate_delay: Optional[float] = None,
    ) -> None:
        self._settings = settings
        self._base_headers = dict(default_headers or {})
        self._client: Optional[httpx.AsyncClient] = None
        self._lock = asyncio.Lock()
        self.request_count = 0
        self._rate_delay = rate_delay
        self._rate_lock = asyncio.Lock()

    @asynccontextmanager
    async def get_client(self) -> AsyncIterator[httpx.AsyncClient]:
        if self._client is None:
            async with self._lock:
                if self._client is None:
                    headers: MutableMapping[str, str] = {
                        "User-Agent": self._settings.user_agent,
                        **self._base_headers,
                    }
                    self._client = httpx.AsyncClient(
                        timeout=self._settings.timeout,
                        headers=headers,
                        verify=self._settings.verify_ssl,
                        follow_redirects=True,
                    )
        assert self._client is not None
        try:
            yield self._client
        finally:
            # client kapanışı, tarama sonunda dışarıdan yapılacak
            pass

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request_with_retry(self, **kwargs: Any) -> httpx.Response:
        retrying = AsyncRetrying(
            reraise=True,
            retry=retry_if_exception_type((httpx.RequestError, httpx.TimeoutException)),
            stop=stop_after_attempt(self._settings.max_retries + 1),
            wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
        )

        async for attempt in retrying:
            with attempt:
                async with self.get_client() as client:
                    response = await client.request(**kwargs)
                    response.raise_for_status()
                    return response
        raise RetryError("İstek tekrarlarında beklenmeyen durum.")

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if self._rate_delay:
            async with self._rate_lock:
                await asyncio.sleep(self._rate_delay)
        self.request_count += 1
        return await self._request_with_retry(method=method, url=url, **kwargs)



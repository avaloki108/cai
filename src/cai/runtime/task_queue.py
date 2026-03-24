from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, List, Optional


TaskFactory = Callable[[], Awaitable[Any]]


@dataclass
class TaskResult:
    ok: bool
    result: Any = None
    error: Optional[str] = None


class AsyncTaskQueue:
    """Lightweight in-process queue with bounded async workers."""

    def __init__(self, workers: int = 8):
        self._workers = max(1, workers)
        self._queue: asyncio.Queue[tuple[int, TaskFactory] | None] = asyncio.Queue()
        self._tasks: List[asyncio.Task] = []
        self._results: dict[int, TaskResult] = {}
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        for _ in range(self._workers):
            self._tasks.append(asyncio.create_task(self._worker()))

    async def _worker(self) -> None:
        while True:
            item = await self._queue.get()
            if item is None:
                self._queue.task_done()
                return
            idx, factory = item
            try:
                result = await factory()
                self._results[idx] = TaskResult(ok=True, result=result)
            except Exception as exc:  # pylint: disable=broad-except
                self._results[idx] = TaskResult(ok=False, error=str(exc))
            finally:
                self._queue.task_done()

    async def run(self, factories: List[TaskFactory]) -> List[TaskResult]:
        await self.start()
        self._results.clear()
        for idx, factory in enumerate(factories):
            await self._queue.put((idx, factory))
        await self._queue.join()
        return [self._results[i] for i in range(len(factories))]

    async def shutdown(self) -> None:
        if not self._started:
            return
        for _ in self._tasks:
            await self._queue.put(None)
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._started = False

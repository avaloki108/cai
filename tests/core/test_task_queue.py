import asyncio

import pytest

from cai.runtime.task_queue import AsyncTaskQueue


@pytest.mark.asyncio
async def test_async_task_queue_runs_tasks() -> None:
    queue = AsyncTaskQueue(workers=2)

    async def _job(val: int) -> int:
        await asyncio.sleep(0.01)
        return val * 2

    results = await queue.run([lambda: _job(2), lambda: _job(5)])
    await queue.shutdown()

    assert results[0].ok is True
    assert results[0].result == 4
    assert results[1].result == 10

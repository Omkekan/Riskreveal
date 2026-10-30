"""Shared offset/limit pagination for list endpoints.

Use ``Pagination`` as a route parameter type::

    def list_things(page: Pagination) -> ...: ...

Limits are bounded so a client cannot ask for an unbounded result set.
"""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Query

DEFAULT_LIMIT = 50
MAX_LIMIT = 100
MAX_OFFSET = 1_000_000


@dataclass(frozen=True)
class PageParams:
    limit: int
    offset: int


def get_page_params(
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
) -> PageParams:
    return PageParams(limit=limit, offset=offset)


Pagination = Annotated[PageParams, Depends(get_page_params)]

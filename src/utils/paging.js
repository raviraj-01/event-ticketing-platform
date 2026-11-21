// Offset paging for list endpoints: ?limit=&offset= (M4).
// The query asks for limit + 1 rows; the extra row only tells us whether a
// next page exists. Offset paging can skip or repeat a row if new rows arrive
// between two page loads; acceptable for these lists, and much simpler than
// cursors.

function readPage(query, { defaultLimit = 50, maxLimit = 100 } = {}) {
  const requested = Number.parseInt(query && query.limit, 10);
  const limit = Math.min(Number.isInteger(requested) && requested > 0 ? requested : defaultLimit, maxLimit);
  const requestedOffset = Number.parseInt(query && query.offset, 10);
  const offset = Number.isInteger(requestedOffset) && requestedOffset > 0 ? requestedOffset : 0;
  return { limit, offset };
}

// rows came from a query with LIMIT page.limit + 1.
function pageOf(rows, page) {
  const hasMore = rows.length > page.limit;
  return {
    rows: hasMore ? rows.slice(0, page.limit) : rows,
    paging: { limit: page.limit, offset: page.offset, nextOffset: hasMore ? page.offset + page.limit : null },
  };
}

module.exports = { readPage, pageOf };

const assert = require('node:assert/strict');
const fs = require('node:fs');
const {Stream} = require(process.argv[2]);
const body = fs.readFileSync(process.argv[3], 'utf8');
const response = new Response(body, {headers: {'content-type': 'text/event-stream'}});
(async () => {
  const events = [];
  for await (const event of Stream.fromSSEResponse(response, new AbortController())) events.push(event);
  assert.deepEqual(events.map(event => event.type), [
    'response.output_item.added', 'response.output_text.delta', 'response.completed',
  ]);
  assert.equal(events[1].delta, 'CANNED_SOL_OK');
  assert.equal(events[2].response.status, 'completed');
  console.log('pinned OpenAI SSE parser accepted canned sol response');
})().catch(error => { console.error(error); process.exitCode = 1; });

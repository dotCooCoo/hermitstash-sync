'use strict';

// HttpClient error messages for a refused upload, download, delete, rename and
// certificate renewal. Upload and download run against a local plain-HTTP
// server on 127.0.0.1; delete, rename and renewal stub the transport method
// they call. No HermitStash server is needed:
//
//   node --test tests/test-error-detail.js

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { createTempDir, rmrf } = require('./test-helpers');

const HttpClient = require(path.resolve(__dirname, '..', 'lib', 'http-client'));

const PROBLEM_404 = {
  type: 'https://hermitstash.com/problems/not-found', title: 'Not Found', status: 404, detail: 'File not found.',
};
const PROBLEM_500 = {
  type: 'https://hermitstash.com/problems/internal-error', title: 'Internal Error', status: 500,
};
// Over the 64 KiB cap the client reads an error body up to.
const OVERSIZED_BODY = JSON.stringify({ detail: 'x'.repeat(70 * 1024) });                // allow:raw-byte-literal — test body size

// Starts a server that answers every request with the given status, content
// type and body, then runs fn(client, root) and tears both down.
async function withServer(status, contentType, body, fn) {
  const root = createTempDir('error-detail');
  const server = http.createServer((req, res) => {
    req.on('data', () => {});
    req.on('end', () => {
      res.writeHead(status, { 'Content-Type': contentType, 'Content-Length': Buffer.byteLength(body) });
      res.end(body);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const client = new HttpClient({ server: 'http://127.0.0.1:' + server.address().port }, 'hs_test_key');
  try {
    await fn(client, root);
  } finally {
    try { client.destroy(); } catch { /* best-effort */ }
    await new Promise((r) => server.close(r));
    rmrf(root);
  }
}

function writeUpload(root) {
  const p = path.join(root, 'a.txt');
  fs.writeFileSync(p, 'hello');
  return p;
}

describe('errorText', () => {
  it('returns the detail, then the legacy error, and the title only when asked', () => {
    assert.equal(HttpClient.errorText({ detail: 'd', error: 'e', title: 't' }), 'd');
    assert.equal(HttpClient.errorText({ error: 'e', title: 't' }), 'e');
    assert.equal(HttpClient.errorText({ title: 't' }), '');
    assert.equal(HttpClient.errorText({ title: 't' }, true), 't');
  });

  it('returns an empty string for a missing body or a field that is not a non-empty string', () => {
    assert.equal(HttpClient.errorText(null), '');
    assert.equal(HttpClient.errorText('text'), '');
    assert.equal(HttpClient.errorText({ detail: { toString: 1 } }), '');
    assert.equal(HttpClient.errorText({ detail: '', error: 'e' }), 'e');
  });
});

describe('upload error message', () => {
  it('carries the problem-details detail, the status, and permanent=true on a 4xx', async () => {
    await withServer(404, 'application/problem+json', JSON.stringify(PROBLEM_404), async (client, root) => {
      await assert.rejects(client.uploadFile('bundle-x', 'a.txt', writeUpload(root)), (err) => {
        assert.equal(err.message, 'Upload failed: HTTP 404: File not found.');
        assert.equal(err.statusCode, 404);
        assert.equal(err.permanent, true);
        return true;
      });
    });
  });

  it('falls back to a legacy {error} body, and a 503 stays retryable', async () => {
    await withServer(503, 'application/json', JSON.stringify({ error: 'busy' }), async (client, root) => {
      await assert.rejects(client.uploadFile('bundle-x', 'a.txt', writeUpload(root)), (err) => {
        assert.equal(err.message, 'Upload failed: HTTP 503: busy');
        assert.equal(err.permanent, false);
        return true;
      });
    });
  });

  it('falls back to the raw body when it is not JSON', async () => {
    await withServer(500, 'text/plain', 'File unavailable', async (client, root) => {
      await assert.rejects(client.uploadFile('bundle-x', 'a.txt', writeUpload(root)),
        { message: 'Upload failed: HTTP 500: File unavailable' });
    });
  });

  it('names the problem title when a 5xx withholds the detail', async () => {
    await withServer(500, 'application/problem+json', JSON.stringify(PROBLEM_500), async (client, root) => {
      await assert.rejects(client.uploadFile('bundle-x', 'a.txt', writeUpload(root)), (err) => {
        assert.equal(err.message, 'Upload failed: HTTP 500: Internal Error');
        assert.equal(err.statusCode, 500);
        return true;
      });
    });
  });

  it('names only the status when the body is empty', async () => {
    await withServer(502, 'text/plain', '', async (client, root) => {
      await assert.rejects(client.uploadFile('bundle-x', 'a.txt', writeUpload(root)), { message: 'Upload failed: HTTP 502' });
    });
  });

  it('a non-string detail does not change the 4xx classification', async () => {
    await withServer(400, 'application/json', '{"detail":{"toString":1}}', async (client, root) => {
      await assert.rejects(client.uploadFile('bundle-x', 'a.txt', writeUpload(root)), (err) => {
        assert.equal(err.statusCode, 400, 'got: ' + err.message);
        assert.equal(err.permanent, true);
        return true;
      });
    });
  });

  it('keeps the status and the 4xx classification when the error body is too large to read', async () => {
    await withServer(400, 'application/json', OVERSIZED_BODY, async (client, root) => {
      await assert.rejects(client.uploadFile('bundle-x', 'a.txt', writeUpload(root)), (err) => {
        assert.match(err.message, /^Upload failed: HTTP 400: error body not read \(/);
        assert.equal(err.statusCode, 400);
        assert.equal(err.permanent, true);
        return true;
      });
    });
  });
});

describe('download error message', () => {
  it('carries the problem-details detail', async () => {
    await withServer(404, 'application/problem+json', JSON.stringify(PROBLEM_404), async (client, root) => {
      await assert.rejects(client.downloadFile('fid', path.join(root, 'out.bin')),
        { message: 'Download failed: HTTP 404: File not found.' });
    });
  });

  it('falls back to the raw body when it is not JSON', async () => {
    await withServer(500, 'text/plain', 'File unavailable', async (client, root) => {
      await assert.rejects(client.downloadFile('fid', path.join(root, 'out.bin')),
        { message: 'Download failed: HTTP 500: File unavailable' });
    });
  });

  it('names the status when the error body is too large to read', async () => {
    await withServer(400, 'application/json', OVERSIZED_BODY, async (client, root) => {
      await assert.rejects(client.downloadFile('fid', path.join(root, 'out.bin')),
        /^Error: Download failed: HTTP 400: error body not read \(/);
    });
  });
});

describe('delete error message', () => {
  function stubbed(resp) {
    const c = new HttpClient({ server: 'http://127.0.0.1:9' }, 'hs_test_key');
    c._jsonRequest = async () => resp;
    return c;
  }

  it('appends the problem-details detail', async () => {
    const c = stubbed({ statusCode: 403, json: { type: 't', title: 'Forbidden', status: 403, detail: 'API key not bound to this bundle.' } });
    await assert.rejects(c.deleteFile('f1'), { message: 'Delete failed: HTTP 403: API key not bound to this bundle.' });
  });

  it('appends a legacy {error}', async () => {
    const c = stubbed({ statusCode: 409, json: { error: 'sync disabled' } });
    await assert.rejects(c.deleteFile('f1'), { message: 'Delete failed: HTTP 409: sync disabled' });
  });

  it('names only the status when the body is not JSON', async () => {
    const c = stubbed({ statusCode: 500, json: null });
    await assert.rejects(c.deleteFile('f1'), { message: 'Delete failed: HTTP 500' });
  });

  it('treats a 404 as already deleted', async () => {
    const c = stubbed({ statusCode: 404, json: PROBLEM_404 });
    await c.deleteFile('f1');
  });

  it('a non-string detail still produces a Delete failed message', async () => {
    const c = stubbed({ statusCode: 400, json: { detail: { toString: 1 } } });
    await assert.rejects(c.deleteFile('f1'), (err) => {
      assert.match(err.message, /^Delete failed: HTTP 400/, 'got: ' + err.message);
      return true;
    });
  });
});

describe('encrypted request error message', () => {
  function stubbed(request) {
    const c = new HttpClient({ server: 'http://127.0.0.1:9' }, 'hs_test_key');
    c._getEncClient = async () => ({ request });
    return c;
  }

  it('names the clock when the server rejects the request again with a fresh session', async () => {
    let calls = 0;
    const c = stubbed(async () => { calls += 1; return { statusCode: 400, body: { error: 'encrypted-payload-rejected' } }; });
    await assert.rejects(c.renameFile('b1', 'a.txt', 'b.txt'), (err) => {
      assert.equal(err.code, 'ENC_PAYLOAD_REJECTED');
      assert.match(err.message, /more than 5 minutes from its own clock/);
      return true;
    });
    assert.equal(calls, 2, 'one retry with a fresh session before the error');
  });

  it('names a reverse proxy when an error body is not JSON, and keeps the status', async () => {
    const c = stubbed(async () => ({ statusCode: 502, body: '<html><title>502 Bad Gateway</title></html>', ok: false }));
    await assert.rejects(c.renameFile('b1', 'a.txt', 'b.txt'), (err) => {
      assert.equal(err.statusCode, 502);
      assert.equal(err.permanent, false);
      assert.match(err.message, /^Rename failed: HTTP 502: .*reverse proxy error page/);
      return true;
    });
  });

  it('a 4xx problem-details refusal keeps its detail and is permanent', async () => {
    const c = stubbed(async () => ({ statusCode: 404, body: { title: 'Not Found', status: 404, detail: 'File not found at old path.' }, ok: false }));
    await assert.rejects(c.renameFile('b1', 'a.txt', 'b.txt'), (err) => {
      assert.equal(err.message, 'File not found at old path.');
      assert.equal(err.statusCode, 404);
      assert.equal(err.permanent, true);
      return true;
    });
  });

  it('a success status with a body that is not JSON is reported as ENC_RESPONSE_NOT_JSON', async () => {
    const c = stubbed(async () => {
      const e = new Error('httpClient.encrypted: response body is not valid JSON: invalid JSON syntax');
      e.code = 'api-encrypt/client-response-not-json';
      throw e;
    });
    await assert.rejects(c.renameFile('b1', 'a.txt', 'b.txt'), (err) => {
      assert.equal(err.code, 'ENC_RESPONSE_NOT_JSON');
      assert.equal(err.permanent, false);
      assert.match(err.message, /success status and a body that is not JSON/);
      return true;
    });
  });
});

describe('certificate renewal error message', () => {
  function stubbed(resp) {
    const c = new HttpClient({ server: 'http://127.0.0.1:9' }, 'hs_test_key');
    c._rawRequest = async () => resp;
    return c;
  }

  it('a JSON null body reports the status instead of a TypeError', async () => {
    await assert.rejects(stubbed({ statusCode: 200, body: 'null' }).renewCert(),
      { message: 'Renewal failed with HTTP 200' });
  });

  it('carries the problem-details detail on a refusal', async () => {
    await assert.rejects(stubbed({ statusCode: 403, body: JSON.stringify({ title: 'Forbidden', status: 403, detail: 'Certificate revoked.' }) }).renewCert(),
      { message: 'Certificate revoked.' });
  });
});

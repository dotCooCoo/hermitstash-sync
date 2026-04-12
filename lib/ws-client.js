'use strict';

const crypto = require('node:crypto');
const https = require('node:https');
const http = require('node:http');
const fs = require('node:fs');
const { EventEmitter } = require('node:events');
const { VERSION, TLS_GROUPS, TLS_MIN_VERSION, RECONNECT_DELAYS, HEARTBEAT_TIMEOUT_MS } = require('./constants');
const log = require('./logger');

// WebSocket opcodes
const OP = { CONTINUATION: 0, TEXT: 1, BINARY: 2, CLOSE: 8, PING: 9, PONG: 10 };

class WsClient extends EventEmitter {
  constructor(config, apiKey) {
    super();
    this._config = config;
    this._apiKey = apiKey;
    this._socket = null;
    this._connected = false;
    this._reconnectAttempt = 0;
    this._reconnectTimer = null;
    this._heartbeatTimer = null;
    this._closing = false;
    this._buffer = Buffer.alloc(0);
    this._fragmentBuffer = null; // L1: WebSocket continuation frame tracking

    // M6: Cache mTLS certs at construction time — avoid re-reading on every reconnect
    this._cachedCert = null;
    this._cachedKey = null;
    this._cachedCa = null;
    if (config.mtls) {
      if (config.mtls.cert) this._cachedCert = fs.readFileSync(config.mtls.cert);
      if (config.mtls.key) this._cachedKey = fs.readFileSync(config.mtls.key);
      if (config.mtls.ca) this._cachedCa = fs.readFileSync(config.mtls.ca);
    }
  }

  /**
   * Connect to the server's /sync/ws endpoint
   */
  connect(bundleId, since = 0) {
    this._bundleId = bundleId;
    this._since = since;
    this._closing = false;
    this._doConnect();
  }

  /**
   * Send a JSON message to the server
   */
  send(obj) {
    if (!this._connected || !this._socket) {
      log.warn('Cannot send — not connected');
      return false;
    }
    const data = JSON.stringify(obj);
    this._sendFrame(OP.TEXT, Buffer.from(data, 'utf8'));
    return true;
  }

  /**
   * L10: Update the `since` sequence number so reconnections use the latest value.
   */
  updateSince(seq) {
    this._since = seq;
  }

  /**
   * Close the connection gracefully
   */
  close() {
    this._closing = true;
    this._clearTimers();

    if (this._socket) {
      try {
        // Send close frame
        this._sendFrame(OP.CLOSE, Buffer.alloc(0));
        this._socket.end();
      } catch {}
      this._socket = null;
    }
    this._connected = false;
  }

  _doConnect() {
    const serverUrl = new URL(this._config.server);
    const isHttps = serverUrl.protocol === 'https:';
    const port = serverUrl.port || (isHttps ? 443 : 80);

    const wsPath = `/sync/ws?bundleId=${encodeURIComponent(this._bundleId)}&since=${this._since}`;
    const wsKey = crypto.randomBytes(16).toString('base64');

    const options = {
      hostname: serverUrl.hostname,
      port,
      path: wsPath,
      method: 'GET',
      headers: {
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Key': wsKey,
        'Sec-WebSocket-Version': '13',
        'Authorization': `Bearer ${this._apiKey}`,
        'User-Agent': `hermitstash-sync/${VERSION}`,
      },
    };

    if (isHttps) {
      // M2: Set both ecdhCurve and groups for PQC TLS compatibility
      options.ecdhCurve = TLS_GROUPS;
      options.groups = TLS_GROUPS;
      options.minVersion = TLS_MIN_VERSION;

      // M6: Use cached mTLS certs instead of re-reading on every reconnect
      if (this._cachedCert) options.cert = this._cachedCert;
      if (this._cachedKey) options.key = this._cachedKey;
      if (this._cachedCa) options.ca = this._cachedCa;
    }

    log.debug('WebSocket connecting', { host: serverUrl.hostname, port, path: wsPath });

    const mod = isHttps ? https : http;
    const req = mod.request(options);

    req.on('upgrade', (res, socket, head) => {
      // Verify the accept header
      const expectedAccept = crypto
        .createHash('sha1')
        .update(wsKey + '258EAFA5-E914-47DA-95CA-5AB5DC85B175')
        .digest('base64');

      if (res.headers['sec-websocket-accept'] !== expectedAccept) {
        log.error('WebSocket handshake failed: invalid accept header');
        socket.destroy();
        this._scheduleReconnect();
        return;
      }

      this._socket = socket;
      this._connected = true;
      this._reconnectAttempt = 0;
      this._buffer = head.length ? head : Buffer.alloc(0);

      log.info('WebSocket connected');
      this.emit('open');

      this._resetHeartbeatTimer();

      socket.on('data', chunk => {
        this._buffer = Buffer.concat([this._buffer, chunk]);
        this._processFrames();
      });

      socket.on('close', () => {
        this._connected = false;
        this._socket = null;
        log.info('WebSocket closed');
        this.emit('close');
        if (!this._closing) this._scheduleReconnect();
      });

      socket.on('error', err => {
        log.error('WebSocket socket error', err);
        this._connected = false;
        this._socket = null;
        this.emit('error', err);
        if (!this._closing) this._scheduleReconnect();
      });
    });

    req.on('response', res => {
      // Server didn't upgrade — auth failure or other error
      let body = '';
      // L3: Limit accumulated error body to 64 KB
      res.on('data', c => { if (body.length < 65536) body += c; });
      res.on('end', () => {
        log.error('WebSocket upgrade rejected', { status: res.statusCode, body });
        if (res.statusCode === 401 || res.statusCode === 403) {
          this.emit('auth_error', { status: res.statusCode, body });
          // Don't reconnect on auth errors — the key is wrong
        } else {
          if (!this._closing) this._scheduleReconnect();
        }
      });
    });

    req.on('error', err => {
      log.error('WebSocket connection error', err);
      if (!this._closing) this._scheduleReconnect();
    });

    req.end();
  }

  _processFrames() {
    while (this._buffer.length >= 2) {
      const byte0 = this._buffer[0];
      const byte1 = this._buffer[1];

      const fin = (byte0 & 0x80) !== 0; // L1: Track FIN bit for fragmentation
      const opcode = byte0 & 0x0F;
      const masked = (byte1 & 0x80) !== 0;
      let payloadLen = byte1 & 0x7F;

      let offset = 2;

      if (payloadLen === 126) {
        if (this._buffer.length < 4) return; // need more data
        payloadLen = this._buffer.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (this._buffer.length < 10) return;
        // Read as BigInt but convert — we won't handle >2GB frames
        payloadLen = Number(this._buffer.readBigUInt64BE(2));
        offset = 10;
      }

      if (masked) {
        offset += 4; // mask key
      }

      const totalLen = offset + payloadLen;
      if (this._buffer.length < totalLen) return; // need more data

      let payload = this._buffer.subarray(offset, totalLen);

      if (masked) {
        const maskKey = this._buffer.subarray(offset - 4, offset);
        payload = Buffer.from(payload); // copy
        for (let i = 0; i < payload.length; i++) {
          payload[i] ^= maskKey[i % 4];
        }
      }

      // Consume this frame from the buffer
      this._buffer = this._buffer.subarray(totalLen);

      this._handleFrame(fin, opcode, payload);
    }
  }

  _handleFrame(fin, opcode, payload) {
    // L1: Handle WebSocket continuation frames (fragmented messages)
    if (!fin && (opcode === OP.TEXT || opcode === OP.BINARY)) {
      // First fragment of a fragmented message
      this._fragmentBuffer = payload;
      return;
    }
    if (opcode === OP.CONTINUATION) {
      if (this._fragmentBuffer) {
        this._fragmentBuffer = Buffer.concat([this._fragmentBuffer, payload]);
      }
      if (fin) {
        // Final continuation frame — emit the assembled message
        const text = this._fragmentBuffer.toString('utf8');
        this._fragmentBuffer = null;
        try {
          const msg = JSON.parse(text);
          this._resetHeartbeatTimer();
          this.emit('message', msg);
        } catch (err) {
          log.warn('Invalid JSON from server (fragmented)', { text: text.slice(0, 200) });
        }
      }
      return;
    }

    switch (opcode) {
      case OP.TEXT: {
        const text = payload.toString('utf8');
        try {
          const msg = JSON.parse(text);
          this._resetHeartbeatTimer();
          this.emit('message', msg);
        } catch (err) {
          log.warn('Invalid JSON from server', { text: text.slice(0, 200) });
        }
        break;
      }

      case OP.PING:
        this._sendFrame(OP.PONG, payload);
        break;

      case OP.PONG:
        // Heartbeat response
        break;

      case OP.CLOSE: {
        log.info('Server sent close frame');
        if (this._socket) {
          this._sendFrame(OP.CLOSE, Buffer.alloc(0));
          this._socket.end();
        }
        break;
      }

      default:
        break;
    }
  }

  _sendFrame(opcode, payload) {
    if (!this._socket || !this._connected) return;

    // Client frames MUST be masked (RFC 6455)
    const maskKey = crypto.randomBytes(4);
    const masked = Buffer.from(payload);
    for (let i = 0; i < masked.length; i++) {
      masked[i] ^= maskKey[i % 4];
    }

    let header;
    if (payload.length < 126) {
      header = Buffer.alloc(6);
      header[0] = 0x80 | opcode; // FIN + opcode
      header[1] = 0x80 | payload.length; // MASK + length
      maskKey.copy(header, 2);
    } else if (payload.length < 65536) {
      header = Buffer.alloc(8);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(payload.length, 2);
      maskKey.copy(header, 4);
    } else {
      header = Buffer.alloc(14);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(payload.length), 2);
      maskKey.copy(header, 10);
    }

    try {
      this._socket.write(Buffer.concat([header, masked]));
    } catch (err) {
      log.error('Failed to send WebSocket frame', err);
    }
  }

  _resetHeartbeatTimer() {
    if (this._heartbeatTimer) clearTimeout(this._heartbeatTimer);
    this._heartbeatTimer = setTimeout(() => {
      log.warn('Heartbeat timeout — no message from server in ' + (HEARTBEAT_TIMEOUT_MS / 1000) + 's');
      if (this._socket) {
        this._socket.destroy();
        this._socket = null;
      }
      this._connected = false;
      if (!this._closing) this._scheduleReconnect();
    }, HEARTBEAT_TIMEOUT_MS);
  }

  _scheduleReconnect() {
    if (this._closing) return;
    const delay = RECONNECT_DELAYS[Math.min(this._reconnectAttempt, RECONNECT_DELAYS.length - 1)];
    this._reconnectAttempt++;
    log.info(`Reconnecting in ${delay / 1000}s (attempt ${this._reconnectAttempt})`);
    this._reconnectTimer = setTimeout(() => {
      this.emit('reconnecting', this._reconnectAttempt);
      this._doConnect();
    }, delay);
  }

  _clearTimers() {
    if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
    if (this._heartbeatTimer) clearTimeout(this._heartbeatTimer);
    this._reconnectTimer = null;
    this._heartbeatTimer = null;
  }
}

module.exports = WsClient;

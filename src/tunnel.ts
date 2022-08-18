import tls from 'tls';
import http from 'http';
import https from 'https';
import events from 'events';
import { Agent } from 'http';
import { Agent as HttpsAgent } from 'https';

export interface ProxyOptions {
  host: string;
  port: number;
  localAddress?: string | undefined;
  proxyAuth?: string | undefined;
  headers?: { [key: string]: any } | undefined;
}

export interface HttpsProxyOptions extends ProxyOptions {
  ca?: Buffer[] | undefined;
  servername?: string | undefined;
  key?: Buffer | undefined;
  cert?: Buffer | undefined;
}

export interface HttpOptions {
  maxSockets?: number | undefined;
  proxy?: ProxyOptions | undefined;
}

export function httpOverHttp(options?: HttpOptions): Agent {
  let agent = new TunnelingAgent(options);
  agent.request = http.request;
  return agent;
}

export interface HttpsOverHttpOptions extends HttpOptions {
  ca?: Buffer[] | undefined;
  key?: Buffer | undefined;
  cert?: Buffer | undefined;
}

export function httpsOverHttp(options?: HttpsOverHttpOptions): Agent {
  let agent = new TunnelingAgent(options);
  agent.request = http.request;
  agent.createSocket = createSecureSocket;
  agent.defaultPort = 443;
  return agent;
}

export interface HttpOverHttpsOptions extends HttpOptions {
  proxy?: HttpsProxyOptions | undefined;
}

export function httpOverHttps(options?: HttpOverHttpsOptions): HttpsAgent {
  let agent = new TunnelingAgent(options);
  agent.request = https.request;
  return agent;
}

export interface HttpsOverHttpsOptions extends HttpsOverHttpOptions {
  proxy?: HttpsProxyOptions | undefined;
}

export function httpsOverHttps(options?: HttpsOverHttpsOptions): HttpsAgent {
  let agent = new TunnelingAgent(options);
  agent.request = https.request;
  agent.createSocket = createSecureSocket;
  agent.defaultPort = 443;
  return agent;
}

type Socket = { removeAllListeners: () => void; destroy: () => void; }

class TunnelingAgent extends events.EventEmitter {
  options: HttpOptions | HttpsOverHttpOptions | HttpOverHttpsOptions | HttpsOverHttpsOptions;
  proxyOptions: ProxyOptions | HttpsProxyOptions | {};
  maxSockets: number;
  requests: typeof http.request[] = [];
  sockets: Socket[] = [];
  request?: typeof http.request;

  constructor(options: HttpOptions | HttpsOverHttpOptions | HttpOverHttpsOptions | HttpsOverHttpsOptions = {}) {
    super()

    this.options = options;
    this.proxyOptions = this.options.proxy ?? {};
    this.maxSockets = this.options.maxSockets ?? http.Agent.defaultMaxSockets;

    this.on('free', (socket, host, port, localAddress) => {
      const options = toOptions(host, port, localAddress);
      for (let i = 0, len = this.requests.length; i < len; ++i) {
        const pending = this.requests[i];
        if (pending.host === options.host && pending.port === options.port) {
          // Detect the request to connect same origin server,
          // reuse the connection.
          this.requests.splice(i, 1);
          pending.request.onSocket(socket);
          return;
        }
      }
      socket.destroy();
      this.removeSocket(socket);
    });
  }

  addRequest(req: typeof http.request, host: string | ProxyOptions, port: number, localAddress: string | undefined) {
    let options = mergeOptions({ request: req }, this.options, toOptions(host, port, localAddress));

    if (this.sockets.length >= this.maxSockets) {
      // We are over limit so we'll add it to the queue.
      this.requests.push(options);
      return;
    }

    // If we are under maxSockets create a new one.
    this.createSocket(options, (socket) => {
      const onFree = () => {
        this.emit('free', socket, options);
      }

      const onCloseOrRemove = (_err: never) => {
        this.removeSocket(socket);
        socket.removeListener('free', onFree);
        socket.removeListener('close', onCloseOrRemove);
        socket.removeListener('agentRemove', onCloseOrRemove);
      }

      socket.on('free', onFree);
      socket.on('close', onCloseOrRemove);
      socket.on('agentRemove', onCloseOrRemove);
      req.onSocket(socket);
    });
  };

  createSocket(options: ProxyOptions, cb: (socket: Socket) => void) {
    let placeholder: Socket = {};
    this.sockets.push(placeholder);

    let connectOptions = mergeOptions({}, this.proxyOptions, {
      method: 'CONNECT',
      path: options.host + ':' + options.port,
      agent: false,
      headers: {
        host: options.host + ':' + options.port
      }
    });
    if (options.localAddress) {
      connectOptions.localAddress = options.localAddress;
    }
    if (connectOptions.proxyAuth) {
      connectOptions.headers = connectOptions.headers || {};
      connectOptions.headers['Proxy-Authorization'] = 'Basic ' +
        new Buffer(connectOptions.proxyAuth).toString('base64');
    }

    const onConnect = (res: { statusCode: string | number; }, socket: Socket, head: string | any[]) => {
      connectReq.removeAllListeners();
      socket.removeAllListeners();

      if (res.statusCode !== 200) {
        debug('tunneling socket could not be established, statusCode=%d',
          res.statusCode);
        socket.destroy();
        let error = new Error('tunneling socket could not be established, ' +
          'statusCode=' + res.statusCode);
        error.code = 'ECONNRESET';
        options.request.emit('error', error);
        this.removeSocket(placeholder);
        return;
      }
      if (head.length > 0) {
        debug('got illegal response body from proxy');
        socket.destroy();
        let error = new Error('got illegal response body from proxy');
        error.code = 'ECONNRESET';
        options.request.emit('error', error);
        this.removeSocket(placeholder);
        return;
      }
      debug('tunneling connection has established');
      this.sockets[this.sockets.indexOf(placeholder)] = socket;
      return cb(socket);
    }


    const onError = (cause: { message: string; stack: any; }) => {
      connectReq.removeAllListeners();

      debug('tunneling socket could not be established, cause=%s\n',
        cause.message, cause.stack);
      let error = new Error('tunneling socket could not be established, ' +
        'cause=' + cause.message);
      error.code = 'ECONNRESET';
      options.request.emit('error', error);
      this.removeSocket(placeholder);
    }

    debug('making CONNECT request');
    let connectReq = this.request(connectOptions);
    connectReq.useChunkedEncodingByDefault = false; // for v0.6
    connectReq.once('response', onResponse); // for v0.6
    connectReq.once('upgrade', onUpgrade);   // for v0.6
    connectReq.once('connect', onConnect);   // for v0.7 or later
    connectReq.once('error', onError);
    connectReq.end();

    function onResponse(res: { upgrade: boolean; }) {
      // Very hacky. This is necessary to avoid http-parser leaks.
      res.upgrade = true;
    }

    function onUpgrade(res: any, socket: any, head: any) {
      // Hacky.
      process.nextTick(function () {
        onConnect(res, socket, head);
      });
    }
  };


  removeSocket(socket: any) {
    let pos = this.sockets.indexOf(socket)
    if (pos === -1) {
      return;
    }
    this.sockets.splice(pos, 1);

    const pending = this.requests.shift();
    if (pending) {
      // If we have pending requests and a socket gets closed a new one
      // needs to be created to take over in the pool for the one that closed.
      this.createSocket(pending, function (socket) {
        pending.request.onSocket(socket);
      });
    }
  };
}

function createSecureSocket(options: Record<string, any>, cb: (arg0: tls.TLSSocket) => void) {
  TunnelingAgent.prototype.createSocket.call(this, options, (socket) => {
    let hostHeader = options.request.getHeader('host');
    let tlsOptions = mergeOptions({}, this.options, {
      socket: socket,
      servername: hostHeader ? hostHeader.replace(/:.*$/, '') : options.host
    });

    // 0 is dummy port for v0.6
    let secureSocket = tls.connect(0, tlsOptions);
    this.sockets[this.sockets.indexOf(socket)] = secureSocket;
    cb(secureSocket);
  });
}


function toOptions(host: string | ProxyOptions, port: number, localAddress?: string): ProxyOptions {
  if (typeof host === 'string') { // since v0.10
    return {
      host: host,
      port: port,
      localAddress: localAddress
    };
  }
  return host; // for v0.11 or later
}

function mergeOptions(target: Record<string, any>, ...args: Record<string, any>[]) {
  for (let i = 1, len = args.length; i < len; ++i) {
    let overrides = args[i];
    if (typeof overrides === 'object') {
      let keys = Object.keys(overrides);
      for (let j = 0, keyLen = keys.length; j < keyLen; ++j) {
        let k = keys[j];
        if (overrides[k] !== undefined) {
          target[k] = overrides[k];
        }
      }
    }
  }
  return target;
}

export function debug(...messages: any[]) {
  if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
    let firstMessage = messages[0]
    if (typeof firstMessage === 'string') {
      firstMessage = 'TUNNEL: ' + firstMessage;
      console.error(firstMessage);
    } else {
      messages.unshift('TUNNEL:');
      console.error(...messages);
    }
  }
}
/*
 * Copyright 2026 Bad Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The `ws` listener of the service host (srad/agentspaces-js.md JS-R-04;
 * the binding of ISSUE-Websocket and `agentspaces-transport-http`): one
 * binary frame per AgentSpaces frame, the `aspace.1` subprotocol required,
 * and the browser-origin policy of `OriginPolicy` — a request without an
 * `Origin` header (every non-browser peer) is admitted, one with it only
 * when the origin is on the list, and `*` admits any browser.
 */

import { createServer, IncomingMessage, Server } from "node:http";
import { AddressInfo } from "node:net";
import { WebSocketServer } from "ws";
import { SUBPROTOCOL, WsChannel } from "@agentspaces/client";
import type { FrameChannel, Listener, ListenerHandle, WebSocketLike } from "@agentspaces/client";

/** OriginPolicy.allows: no origin passes; a listed one, or any when `*` is listed. */
export function originAllowed(origins: string[], origin: string | undefined): boolean {
  if (origin === undefined) {
    return true;
  }
  const wanted = origin.trim().toLowerCase().replace(/\/$/, "");
  return origins.some((o) => o === "*" || o.trim().toLowerCase().replace(/\/$/, "") === wanted);
}

export class WsListener implements Listener {
  readonly scheme = "ws";
  /** Upgrades refused for their origin or subprotocol. */
  refused = 0;

  constructor(private readonly origins: string[] = []) {}

  listen(bind: string, onAccept: (channel: FrameChannel) => void): Promise<ListenerHandle> {
    const colon = bind.lastIndexOf(":");
    const host = colon > 0 ? bind.substring(0, colon).replace(/^\[|\]$/g, "") : "0.0.0.0";
    const port = Number(colon >= 0 ? bind.substring(colon + 1) : bind);
    return new Promise((resolve, reject) => {
      const server: Server = createServer((request, response) => {
        response.writeHead(426, { "content-type": "text/plain", upgrade: "websocket" }).end("aspace.1 websocket only");
      });
      const sockets = new WebSocketServer({
        noServer: true,
        handleProtocols: (protocols) => (protocols.has(SUBPROTOCOL) ? SUBPROTOCOL : false),
      });
      server.on("upgrade", (request: IncomingMessage, socket, head) => {
        const origin = request.headers.origin;
        const offered = String(request.headers["sec-websocket-protocol"] ?? "").split(",").map((p) => p.trim());
        if (!originAllowed(this.origins, origin) || !offered.includes(SUBPROTOCOL)) {
          this.refused += 1;
          socket.write(`HTTP/1.1 ${origin !== undefined && !originAllowed(this.origins, origin) ? "403 Forbidden" : "400 Bad Request"}\r\n\r\n`);
          socket.destroy();
          return;
        }
        sockets.handleUpgrade(request, socket, head, (ws) => {
          ws.binaryType = "arraybuffer";
          const remote = `${request.socket.remoteAddress}:${request.socket.remotePort}`;
          onAccept(new WsChannel("ws", ws as unknown as WebSocketLike, remote));
        });
      });
      server.once("error", reject);
      server.listen(port, host, () => {
        server.removeListener("error", reject);
        const address = server.address() as AddressInfo;
        const close = (): void => {
          for (const client of sockets.clients) {
            client.close(1001, "listener closing");
          }
          sockets.close();
          server.close();
        };
        resolve(Object.assign(close, { address: `${host}:${address.port}` }));
      });
    });
  }
}

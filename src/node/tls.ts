/*
 * Copyright 2026 Bad Monkey, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The `tls` binding (SPEC §5.5, §5.6): length-prefixed frames inside TLS 1.3,
 * both ends presenting channel certificates. The remote end is attested from
 * the certificate it presented, after the handshake; the trust decision is
 * `attestChannelCertificate` alone, no CA. A dialer refuses a seed that
 * attests nobody; a listener accepts a client that presents no certificate,
 * unattested, with every frame it sends still signed (Java `TlsTcpTransport`).
 * No session resumption and no early data: a client never offers a session
 * and a server issues no tickets, so every attestation rests on a full
 * handshake (ASF-021). Node only (`node:tls`), like the `tcp` binding.
 */

import { isIP } from "node:net";
import { Server, TLSSocket, connect as tlsConnect, createServer } from "node:tls";
import type { AddressInfo } from "node:net";
import { Identity } from "../identity.js";
import { Seed, seedAddress } from "../seed.js";
import { DialContext, FrameChannel, Listener, ListenerHandle } from "../transport.js";
import { ChannelCertificate, attestChannelCertificate, generateChannelCertificate } from "./channel-certificate.js";
import { TcpChannel, TcpDialer } from "./tcp.js";

/** A `tcp` channel's framing over a TLS socket, knowing the PeerID the handshake attested (or null). */
export class TlsChannel extends TcpChannel {
  readonly scheme: string = "tls";

  constructor(socket: TLSSocket, remote: string, private readonly attested: string | null) {
    super(socket, remote);
  }

  attestedPeer(): string | null {
    return this.attested;
  }
}

/** One channel certificate per identity, generated on its first dial or listen. */
const credentials = new WeakMap<Identity, ChannelCertificate>();

/** The channel certificate `identity` presents, generated once. */
export function channelCredential(identity: Identity): ChannelCertificate {
  let credential = credentials.get(identity);
  if (credential === undefined) {
    credential = generateChannelCertificate(identity);
    credentials.set(identity, credential);
  }
  return credential;
}

/** The PeerID a socket's peer certificate attests, or null when none was presented or it attests nobody. */
function attestedOf(socket: TLSSocket): string | null {
  const presented = socket.getPeerCertificate(false);
  const raw = presented !== null && typeof presented === "object" ? presented.raw : undefined;
  return raw instanceof Uint8Array && raw.length > 0 ? attestChannelCertificate(new Uint8Array(raw)) : null;
}

/** Dials `tls` seeds with the peer's channel certificate; a hostname expands as for `tcp` (DB-X-03). */
export class TlsDialer extends TcpDialer {
  readonly scheme: string = "tls";

  dial(seed: Seed, context?: DialContext): Promise<FrameChannel> {
    const identity = context?.identity;
    if (identity === undefined) {
      return Promise.reject(new Error("the tls dialer needs the peer's identity to present its channel certificate"));
    }
    const credential = channelCredential(identity);
    return new Promise((resolve, reject) => {
      let settled = false;
      const socket = tlsConnect({
        host: seed.host,
        port: seed.port,
        key: credential.keyPem,
        cert: credential.certificatePem,
        minVersion: "TLSv1.3",
        // The CA chain proves nothing here; the endorsement is checked after the handshake.
        rejectUnauthorized: false,
        checkServerIdentity: () => undefined,
        servername: isIP(seed.host) === 0 ? seed.host : undefined,
      });
      const onError = (error: Error): void => {
        if (!settled) {
          settled = true;
          socket.destroy();
          reject(error);
        }
      };
      // The channel wraps the socket synchronously in the handshake callback, so the
      // first bytes the seed sends are buffered before any await can intervene.
      socket.once("secureConnect", () => {
        if (settled) {
          return;
        }
        settled = true;
        socket.removeListener("error", onError);
        const attested = attestedOf(socket);
        if (attested === null) {
          socket.destroy();
          reject(new Error(`tls://${seedAddress(seed)} presented no endorsed channel certificate`));
          return;
        }
        resolve(new TlsChannel(socket, seedAddress(seed), attested));
      });
      socket.on("error", onError);
    });
  }
}

/**
 * Accepts `tls` channels on a bind address (`host:port`), presenting the
 * host's channel certificate and asking each client for its own without
 * requiring one (Java's `setWantClientAuth`): a client without one connects
 * unattested.
 */
export class TlsListener implements Listener {
  readonly scheme: string = "tls";

  constructor(private readonly identity: Identity) {
  }

  listen(bind: string, onAccept: (channel: FrameChannel) => void): Promise<ListenerHandle> {
    const colon = bind.lastIndexOf(":");
    const host = colon > 0 ? bind.substring(0, colon).replace(/^\[|\]$/g, "") : "0.0.0.0";
    const port = Number(colon >= 0 ? bind.substring(colon + 1) : bind);
    const credential = channelCredential(this.identity);
    return new Promise((resolve, reject) => {
      const server: Server = createServer({
        key: credential.keyPem,
        cert: credential.certificatePem,
        minVersion: "TLSv1.3",
        requestCert: true,
        rejectUnauthorized: false,
        // No tickets: a resumed session would skip the CertificateVerify an attestation rests on.
        ticketKeys: undefined,
      }, (socket) => {
        onAccept(new TlsChannel(socket, `${socket.remoteAddress}:${socket.remotePort}`, attestedOf(socket)));
      });
      server.on("tlsClientError", () => { /* a failed handshake ends that socket alone */ });
      server.once("error", reject);
      server.listen(port, host, () => {
        server.removeListener("error", reject);
        const address = server.address() as AddressInfo;
        resolve(Object.assign(() => server.close(), { address: `${host}:${address.port}` }));
      });
    });
  }
}

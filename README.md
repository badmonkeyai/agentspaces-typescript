# @agentspaces/client (TypeScript)

**AgentSpaces for TypeScript and JavaScript**, from Bad Monkey AI. One portable core runs a peer of a peer-to-peer fleet on Node, in a browser, in Web and Cloudflare Workers, Deno, and Bun, with agents written as decorated methods and entries as classes.

## Quick start: build your first agent in TypeScript

An agent is a method. Its parameter is the work it takes, and its return value is the next entry in the space. In TypeScript the method sits on a class marked with decorators, and entries are classes. The peer is a real member of the fleet, it runs on Node 22 or newer, and the same client runs in browsers and Workers. A TypeScript peer dials out to a seed, so the quick start starts one.

**1. Create the project.** The second package supplies the seed.

```
mkdir shop && cd shop
npm init -y && npm pkg set type=module
npm install @agentspaces/client @agentspaces/node
npm install -D typescript @types/node
```

Until the packages are on npm, install them from a clone: `npm install /path/to/agentspaces-typescript /path/to/agentspaces-typescript/packages/node`.

`tsconfig.json` (standard decorators need no `experimentalDecorators`):

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "outDir": "build",
    "types": ["node"]
  },
  "include": ["fulfiller.ts"]
}
```

**2. Start a seed.** The Node service host is a seed in one command and needs no code. Its fleet file has the same shape as the Spring starter's YAML. The `dev-local` profile signs every frame over plain loopback TCP, which is what this client dials. Use it on a laptop and never on a shared network.

`seed.yaml`:

```yaml
agentspaces:
  security:
    profile: dev-local          # signed frames on loopback TCP; never on a shared network
  bind: 127.0.0.1:7700
  tick-millis: 250
  groups:
    - name: shop
      founding: shop-v1
      spaces: [ orders ]
```

```
npx agentspaces-node run seed.yaml
```

The first run creates a `keys/` directory beside `seed.yaml` to hold the seed's identity.

**3. Write the agent.** `@entry` names each entry's wire schema, and the field names match the wire. `@spaceTake` names the entry class to take, the space, and how long the method may hold an entry.

`fulfiller.ts`:

```typescript
import { Binder, Identity, Peer, Space, Template, agent, entry, groupIdFromFounding, spaceTake } from "@agentspaces/client";
import "@agentspaces/client/node"; // Node: registers the tcp and tls dialers

@entry("shop.Order#v1") // the wire name; field names match the wire too
class Order {
  constructor(public orderId = "", public item = "") {}
}

@entry("shop.Shipment#v1")
class Shipment {
  constructor(public orderId = "", public item = "", public by = "") {}
}

@agent("fulfiller", { description: "Ships orders" })
class Fulfiller {
  @spaceTake(Order, "orders", { lease: "30s", produces: Shipment })
  ship(order: Order): Shipment {
    return new Shipment(order.orderId, order.item, "fulfiller");
  }
}

const identity = Identity.generate();
const peer = new Peer(identity, groupIdFromFounding("shop-v1"));
await peer.connect("127.0.0.1", 7700); // the seed
await new Promise((resolve) => setTimeout(resolve, 1000));
new Binder(peer, { agent: identity.renewingSubordinate("fulfiller", "PT24H") }).bind(new Fulfiller());

if (process.argv[2]) {                  // node build/fulfiller.js kite
  const orders = new Space(peer, "orders");
  orders.write(new Order("o-1", process.argv[2]), "10m");
  console.log(await orders.read(new Template(Shipment), "30s"));
  peer.close();
}
```

**4. Run two instances.** The first only ships. The second also writes an order, prints the shipment, and exits.

```
npx tsc
node build/fulfiller.js
node build/fulfiller.js kite
```

Either instance can take the order, because both run the same agent.

**5. Kill one.** Make `ship` `async` with a `Promise<Shipment>` result, and add `console.log("shipping", order.orderId);` and `await new Promise((resolve) => setTimeout(resolve, 10_000));` at the top. Start both instances, write an order from the second, and run `kill -9` on whichever instance prints `shipping`. If you killed the first instance, the second prints the shipment. If you killed the second, the first prints `shipping o-1` again when the 30 second lease lapses.

The [documents](docs/README.md) add the rest: the three tested walk-throughs under "How to use AI with AgentSpaces", the cross-language guarantee, joining by GroupID, bootstrap and invite keys, and layers 3 and 4 in TypeScript.

## What it is

- A portable core that imports no Node module, on the audited noble crypto libraries.
- Decorators for every verb, the capability clients, the ordered log, and the content swarm.
- Packages for a Node service host and its CLI, the browser, WebRTC, Workers cells, and the Automerge and Yjs bridges.
- Persistent values, a reader for databases on refs, verified windows, and content stores.
- Node 22 or newer; dials `tcp` and `tls` on Node and `ws`, `wss`, `http`, and `https` anywhere.

## Add it to your build

```
npm install @agentspaces/client @agentspaces/node
```

Until the packages are on npm, install them from a clone: `npm install /path/to/agentspaces-typescript /path/to/agentspaces-typescript/packages/node`. [About @agentspaces/client](docs/about.md) lists the packages.

## Where to read next

1. **[The developer guide](https://www.badmonkey.ai/agentspaces/developer-guide.html#ol-typescript)**: its TypeScript and JavaScript sections map this client onto the Java chapters.
2. **[The TypeScript guide](https://www.badmonkey.ai/agentspaces/typescript-guide.html)**: a newcomer's walk from a first agent to the browser host, Workers cells, and values that change.
3. **[The examples](https://github.com/badmonkeyai/AgentSpaces/tree/main/examples)**: the core's numbered examples, several with TypeScript workers and Node voters.
4. **[The documents](docs/README.md)**: everything this README leaves out, one topic per document, each with the reader it is written for.

## License

Apache License 2.0, Copyright 2026 Bad Monkey, Inc. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

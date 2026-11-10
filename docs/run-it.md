# Run it

Written for: TypeScript and JavaScript developers who build with @agentspaces/client.

```
npm install
npm test                # tsc + golden vectors via node --test

# the trilingual demo (from the repo root):
clients/run-trilingual-demo.sh
```

The demo runs a Java coordinator publishing six tasks while a Python worker,
this TypeScript worker, and a LangChain4j worker race for them under the
claim lattice; the coordinator prints each finding with the language-tagged
worker that produced it. Its second act is the council: the Java
`CouncilFleet` coordinator with the Python and TypeScript council workers
voting, contributing to the push-sum epoch, answering the semantic query, and
serving a remote action. Four runtimes, one space, no broker.

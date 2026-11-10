# Exact work selection and local snapshots

Written for: TypeScript and JavaScript developers who build with @agentspaces/client.

`takeEntry` accepts an optional `exactEntryId` argument (before the template
matcher and the bid function). Selection always
filters by the group's space ID, uses the effective renewed write lease, and
rechecks the winning claim before returning. `requireHeld` validates an exact,
current claim before an application records a result; `completeEntry` applies
the same guard. The lease-race protocol remains advisory under partitions;
applications must fence external effects separately.

Writes are folded into the issuer's verified local replica before transport.
`exportSnapshot` contains signed states, claims, and revocations, without keys.
`restoreSnapshot` re-verifies revocations before claims and states. Applications
own atomic file storage, size limits and single-writer exclusion. A snapshot is
not a remote acknowledgment or a distributed durability guarantee. Configure the
same trusted founding identity before restoring founder-rooted revocations.

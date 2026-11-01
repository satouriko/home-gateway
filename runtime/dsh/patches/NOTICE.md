# DSH compatibility extensions

These local MIT-licensed patches extend the pinned public npm packages
`@deepseek-ai/dsh-schedule@0.2.1-rc.5` and
`@deepseek-ai/dsh-client-ui-schedule@0.2.1-rc.5`.
The original copyright and license notices are preserved in `LICENSE.schedule`
and `LICENSE.schedule-ui`, and remain unchanged in installed packages.

The scheduler supports a registered external executor, durable admission IDs,
bounded execution receipts, and history links to independent sessions. Ordinary
conversation reminders keep their original behavior. The companion UI renders
execution states and summaries without inventing reminder message IDs.

`manifest.json` pins original and resulting file hashes. Apply with
`python3 tools/apply_dsh_patches.py --runtime runtime/dsh`; it preflights every
package and patch before replacing files. Reapplying a reviewed patch is safe.
Upstream changes require review and regenerated hashes; do not bypass a mismatch.

The public npm tarball is the verified source artifact; the registry does not
supply a source commit for the scheduler version. `schedule-provenance.json`
records artifact integrity. Source-level upstream work belongs in the schedule
TypeScript modules and client components, followed by normal Typert regeneration.
These compiled-package patches keep this installation reproducible while that
upstream integration remains separate work.

An unpatched old scheduler cannot read the new external-task records. Rollback
requires stopping DSH and restoring both code and compatible pre-extension task
data. Never restore an entire old session store over conversations created later.

The host-only retry operation can requeue the latest skipped or failed external occurrence once. It requires a complete expected task record and preserves the execution ID, scheduled occurrence, original receipt and user cadence. Remote clients do not receive a retry mutation API.

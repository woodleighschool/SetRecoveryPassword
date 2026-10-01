# jamf-recovery-lock

A legacy Jamf maintenance utility retained while Jamf remains deployed. It rotates
Recovery Lock passwords on managed Apple silicon Macs and stores confirmed
passwords in 1Password. PostgreSQL holds pending rotations and the existing
1Password item mapping.

## 🔄 Execution

Each invocation validates configuration, reconciles once, logs a summary and exits.
Kubernetes CronJobs in wood-ops own scheduling, retries and concurrency. Per-device
failures continue through the fleet and produce a non-zero exit status.

A rotation is saved as `prepared` before Jamf submission, then `pending` with the
returned command UUID. Only an acknowledged `SET_RECOVERY_LOCK` command **and** a
matching Jamf-reported password permit a 1Password update. The candidate remains in
PostgreSQL until that update succeeds. Stable passwords rotate after 31 days.

Pending or `NotNow` commands retain their candidate. Acknowledgement with stale
inventory is checked again on later runs. After seven days without confirmation,
the run reports an overdue failure; it still never sends another candidate. A
failed command enters `blocked`, retaining the candidate and the previous
1Password secret. Unknown command history is treated as unconfirmed.

Submission cannot be atomic across PostgreSQL and Jamf. A crash after saving
`prepared`, an ambiguous submission response, or failure to save the returned UUID
requires command-history review before repair. A session advisory lock prevents
overlapping runs from submitting competing rotations.

## ⚙️ Configuration

| Variable                                                  | Purpose / default                                          |
| --------------------------------------------------------- | ---------------------------------------------------------- |
| `INSTANCE_DOMAIN`                                         | Required Jamf HTTPS URL or hostname                        |
| `CLIENT_ID`, `CLIENT_SECRET`                              | Required Jamf OAuth client credentials                     |
| `ONEPASSWORD_TOKEN`                                       | Required 1Password service account token                   |
| `ONEPASSWORD_VAULT_ID`                                    | Required destination vault ID                              |
| `DATABASE_HOST`, `DATABASE_USERNAME`, `DATABASE_PASSWORD` | Required PostgreSQL connection credentials                 |
| `DATABASE_PORT`                                           | `5432`                                                     |
| `PASSWORD_LENGTH`                                         | `10` uppercase letters, generated with `crypto/rand`       |
| `ROTATION_AGE`                                            | `744h` (31 days)                                           |
| `PENDING_AGE`                                             | `168h` (seven days), an alert threshold                    |
| `RUN_TIMEOUT`                                             | `30m`                                                      |
| `JAMF_ID`                                                 | Optional single managed Apple silicon computer ID          |
| `DRY_RUN`                                                 | `false`; inspect without changing Jamf, state or 1Password |
| `LOG_LEVEL`                                               | `info`; also `debug`, `warn`, `error`                      |

`--dry-run` overrides the environment. `--help` and `--version` do not connect to
external systems. There is no internal scheduler.

The backing database remains `setrecoverypassword`, with table
`recovery_password_state`. Startup upgrades its schema transactionally and
idempotently. Stable rows and 1Password IDs survive unchanged. Legacy candidates
without a command UUID enter `blocked` because their success cannot be established
from inventory alone. Dry-run reads the old schema without migrating it.

## 🔎 Recovery failures

Apple requires the correct current password to change an existing Recovery Lock.
Generating another candidate does not repair incorrect current-password knowledge.
Jamf documents [PI147605, fixed in 11.27.0](https://learn.jamf.com/r/en-US/jamf-pro-release-notes-11.27.0/Resolved_Issues?contentId=XAU9HcP4MRVDCLQu2a60Dg):
a password can fall out of sync between Jamf and the Mac, preventing rotation.
This is a possible cause of validation failures, not a diagnosis of a particular Mac.
See [Apple's command](https://developer.apple.com/documentation/devicemanagement/setrecoverylockcommand)
and [Jamf command history](https://developer.jamf.com/jamf-pro/reference/get_v2-mdm-commands).

Review a blocked machine's command UUID, status/error, server version, current
Recovery Lock knowledge and retained 1Password value. The following query exposes
state metadata without passwords:

```sql
SELECT id, phase, command_uuid, requested_at, last_error,
       password IS NOT NULL AS has_candidate,
       password_opuuid IS NOT NULL AS has_secret
FROM recovery_password_state
WHERE phase <> 'stable'
ORDER BY id;
```

After repairing the external state, resume a correlated rotation by setting its
known `SET_RECOVERY_LOCK` UUID, actual request timestamp and `phase = 'pending'`.
Keep its candidate and item mapping intact; the next run verifies acknowledgement
and password equality. For an independently verified stable secret, retain the
item mapping, clear the candidate, set `phase = 'stable'`, and record the actual
confirmation time in `date` (RFC3339). Review and back up each affected row before
editing it. There is no automatic reset of blocked state.

Both Jamf and 1Password access use maintained SDKs. Jamf uses current inventory V4
and MDM V2 services (Jamf Pro 11.30 or later); narrow requests through its transport compensate for missing
`newPassword` and response models in the pinned SDK. Authentication, refresh,
pagination and transport policy remain SDK-owned. Command submission has retries
disabled. The API role needs computer inventory, Recovery Lock read/send and MDM
command-history permissions. 1Password needs read/create/update in the target vault.

## 🛠️ Development

```sh
mise install
mise run deps
mise run check
mise run notices
mise run container-check
```

State integration tests additionally use `RECOVERY_TEST_DATABASE_URL` pointing to
an isolated local PostgreSQL database. They create a temporary schema and remove it
afterward. Never point this setting at production.

## 📦 Releases

Release Please preserves the existing version lineage. CI compiles the command;
the shared Docker builder publishes signed images with SBOMs for `linux/amd64` and
`linux/arm64` to `ghcr.io/woodleighschool/jamf-recovery-lock`. The distroless non-root
image includes dependency notices. There is no standalone-binary release pipeline.

wood-ops consumes semantic version and digest pins. Its application rename and
configuration update are managed separately; legacy backing secret and database
identifiers can remain.

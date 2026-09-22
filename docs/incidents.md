# Incidents, approvals and tickets

The rest of these pages describe a handler that runs actions. This page is about
what happens around them when an alert needs a person: the handler stops the
paging, does what it safely can on its own, asks before it does the rest, opens
a ticket, and leaves the resolution to a human.

## The lifecycle

```
alert fires ──► incident opens ──► automatic steps ──► gated steps wait ──► ticket
                  (one per alert)    silence, mitigate    /approvals          Jira
                                                           approve / reject
alert resolves ──► ticket told, incident "alert resolved", ticket stays open
person closes ──► in Jira, or Resolve on /incidents
                  ──► silences lifted, waiting approvals withdrawn, ticket told
                  ──► if the alert still fires, it pages again
```

1. **The alert fires.** A rule with `incident: true` opens an incident for it:
   one per alert (per fingerprint), reused while it stays open.
2. **Automatic steps run at once**, in order, like any rule: typically an
   `am_silence` so the alert stops paging while it is handled, then mitigations
   (`runbook`, `k8s_rollout_restart`, `k8s_scale`, `salt_state_apply`, ...).
   Every outcome lands on the incident's timeline and in `{{ steps }}`.
3. **Gated steps wait for a person.** An action with `approval: required`
   pauses the chain before it runs. It waits on `/approvals`, and
   `approvals.notify` can tell somebody where. **Approve** runs it and the
   rest of the chain, **Reject** ends the chain there. Any action can be
   gated: the ticket, a restart, a scale-down.
4. **The ticket** (`jira_create`) carries the alert, the silence and every
   step so far, and who approved it. The same alert firing again comments on
   its open ticket instead of opening a second one.
5. **The alert resolves.** The incident becomes `alert resolved`, whatever
   still waited for approval is withdrawn, and the ticket gets a comment. The
   ticket stays open: that the graph went green is not the same as the problem
   being understood.
6. **A person closes it**, either by moving the ticket to a done status in
   Jira (the handler polls it) or with **Resolve** on the incident's page. The
   handler lifts the silences it set, withdraws anything still waiting, notes
   it on the ticket and closes the incident. A silence therefore lives exactly
   as long as someone owns the problem: close it while the alert still fires
   and it pages again.

## A complete rule

```yaml
settings:
  public_url: https://alert-handler.example.com      # links in tickets and notifications
  state_file: /var/lib/alert-handler/state.json      # incidents survive a restart
  alertmanager:
    url: http://alertmanager:9093
  jira:
    url: https://example.atlassian.net
    user: alert-bot@example.com                       # Cloud: account email + API token
    token_secret: jira-token                          # a file in the credentials directory
    project: OPS
    issue_type: Incident
  approvals:
    ttl: 12h
    notify:                                           # somebody hears that a decision waits
      type: http
      url: https://chat.example.com/hooks/ops
      body: {text: "{{ approval.summary }} for {{ labels.alertname }}: {{ approval.url }}"}

rules:
  - name: redis-memory
    incident: true
    match_re: {alertname: 'RedisMemory.*'}
    actions:
      - type: am_silence                  # automatic: stop the paging while it is handled
        duration: 4h
        labels: [alertname, namespace, pod]
      - type: runbook                     # automatic: collect what a person will want to see
        name: redis-diagnose.sh
      - type: k8s_rollout_restart         # gated: a person decides
        approval: required
        namespace: "{{ labels.namespace }}"
        name: "{{ labels.deployment }}"
      - type: jira_create                 # gated too: not every blip deserves a ticket
        approval: required
        summary: "{{ labels.alertname }} in {{ labels.namespace }}"
        priority: High
```

The chain pauses twice: once before the restart, once before the ticket.
Approving the first runs the restart and pauses again at the ticket, which then
lists the silence, the diagnosis, the restart and both approvers.

## Approvals

Any action takes `approval: required` (or `true`); the default is `auto`.

- **What waits** is the rest of the chain from that action, saved exactly as
  it was when it paused. A config reload meanwhile does not change what the
  person approves.
- **What is saved** is the template namespace so far, without `secrets` and
  with every credential value redacted. After an approval, `{{ last.stdout }}`
  still works, but a secret a runbook printed reads `***`.
- **Who decided** is taken from the login in front of the handler (the user of
  an `Authorization: Basic` header that an ingress login passes through, or
  `X-Forwarded-User` from an auth proxy), else the form's `by` field. It lands
  in `{{ approval.by }}`, on the incident and in the ticket.
- **One question per step**: while an approval is pending, the same alert
  firing again does not ask a second time.
- **They end** by approval, rejection, expiry after `approvals.ttl`, or
  withdrawal: the alert resolved (`approvals.cancel_on_resolve`) or the
  incident was closed.
- **In `dry_run`** gates still pause, so the flow can be tried safely; an
  approved step then only logs what it would do.

`approvals.notify` is an ordinary action, run when something starts waiting,
with `{{ approval.id }}`, `.url`, `.summary`, `.rule`, `.action` and
`.expires` next to the alert's own placeholders.

## Silences

| `type` | Fields | Does |
| :--- | :--- | :--- |
| `am_silence` | `duration` (`2h`), `labels` (default: all of the alert's), `comment`, `created_by`, `url`, `tenant`, `token_secret` | Silences the alert: exact matchers on the listed labels. Sets `{{ silence.id }}` and `{{ silence.until }}`. |
| `am_expire` | `id`, or nothing, plus `url`, `tenant` | Expires that silence, or every live silence the incident set. |

An incident holds at most one live silence: a repeated run reports the one it
has. Silence on the labels that identify the problem (`alertname`,
`namespace`, `pod`), not on volatile ones, or the next evaluation slips
through.

`url` and `tenant` default to `settings.alertmanager`. A plain Alertmanager is
`http://alertmanager:9093`; a Mimir tenant's is `http://mimir:9009/alertmanager`
with `tenant: <org id>`, sent as `X-Scope-OrgID`. If alerts reach the handler
from several Alertmanagers, write one rule per source (match on `receiver`,
or on a label that tells them apart) with its own `url`/`tenant`.

A silenced alert is muted in Alertmanager's pipeline, and so is its
resolution: while an incident holds a silence, no webhook will say the alert
resolved. The handler therefore asks that Alertmanager itself every
`incidents.check_interval` (`GET /api/v2/alerts`, silenced alerts included),
and treats an alert that is gone as resolved.

## Jira

| `type` | Fields | Does |
| :--- | :--- | :--- |
| `jira_create` | `summary`, `description`, `project`, `issue_type`, `priority`, `labels`, `components`, `fields` (raw extra fields), `dedup` (`true`), `refire_comment` | Opens a ticket, or comments on the alert's open one. Sets `{{ jira.key }}`, `{{ jira.url }}`, `{{ jira.created }}`. |
| `jira_comment` | `body`, `issue` | Comments on a ticket. |
| `jira_transition` | `transition` (a transition or target status name), `comment`, `issue` | Moves a ticket. |

**One ticket per alert.** Every ticket carries the label
`alertfp-<fingerprint>`; before opening one, `jira_create` looks for an open
ticket with that label and comments on it instead. `jira_comment` and
`jira_transition` without an `issue` use the ticket from this chain, the
incident's, or that search, so a `status: resolved` rule can comment on the
right ticket too.

**The default description** is the alert's summary and description, its
labels, when it started, its source and runbook links, what the handler has
done so far (`{{ steps }}`), who approved, and the incident's link. Give
`description` to write your own; `{{ steps }}` and `{{ incident.url }}` are
there for it.

**Cloud or Server.** `api_version: "3"` is Jira Cloud: bodies in Atlassian
Document Format (plain text is converted, blank lines make paragraphs), the
account email in `user` and an API token as the credential. `api_version: "2"`
is Server and Data Center: plain-text bodies and a personal access token with
no `user`, sent as a bearer token. The token is a file in the credentials
directory, named by `token_secret`.

## Closing an incident

- **In Jira**: move the ticket to any status in the *done* category. Every
  `jira.poll_interval` the handler reads the tickets of its open incidents and
  closes those that are done, as the ticket's assignee.
- **On `/incidents/<id>`**: **Resolve**, with a note on what fixed it. With
  `incidents.resolve_transition` set, the handler also moves the ticket
  through that transition.

Either way the handler lifts the incident's silences, withdraws what still
waits for approval, comments on the ticket what it did, and closes the
incident. Closed incidents stay listed for `incidents.retention`.

An alert firing again after its incident closed opens a new incident. One
firing again while its incident is `alert resolved` (ticket still open)
reopens that incident.

## Settings

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `public_url` | `""` | How people reach the handler; approval and incident links are built on it. Empty = relative links. |
| `state_file` | `""` | A file on a volume that incidents and approvals are written through to. Empty = memory only, lost on restart. |
| `alertmanager.url` | `""` | Where `am_silence`/`am_expire` go, and where silenced alerts are checked. |
| `alertmanager.tenant` | `""` | `X-Scope-OrgID`, for a Mimir tenant's Alertmanager. |
| `alertmanager.token_secret` | `""` | Credential holding a bearer token, when the Alertmanager wants one. |
| `alertmanager.verify_tls`, `.timeout` | `true`, `10` | |
| `jira.url` | `""` | Site or server base URL. Empty = the `jira_*` actions fail with that message. |
| `jira.api_version` | `"3"` | `"3"` Cloud, `"2"` Server / Data Center. |
| `jira.user` | `""` | Cloud: the account email. Empty: the token is sent as a bearer token. |
| `jira.token_secret` | `""` | Credential holding the API token or personal access token. |
| `jira.project`, `.issue_type`, `.labels` | `""`, `Task`, `[alert-handler]` | Defaults for `jira_create`. |
| `jira.poll_interval` | `120` | Seconds between checks of open incidents' tickets. `0` = never; close on `/incidents` instead. |
| `jira.verify_tls`, `.timeout` | `true`, `15` | |
| `approvals.ttl` | `24h` | A pending approval expires after this. |
| `approvals.cancel_on_resolve` | `true` | The alert resolving first withdraws its pending approvals. |
| `approvals.notify` | _none_ | An action run when something starts to wait. |
| `incidents.retention` | `7d` | How long closed incidents and settled approvals stay listed. |
| `incidents.check_interval` | `60` | Housekeeping cadence: expiries, retention, silenced alerts, tickets. |
| `incidents.comment_on_resolve` | `true` | Comment on the ticket when the alert resolves. |
| `incidents.resolve_transition` | `""` | Jira transition run when a person closes an incident on `/incidents`. |

Durations take seconds or `30m`, `4h`, `2d`. A rule opts into incidents with
`incident: true`; without it, the actions above still work, only nothing is
tracked (no timeline, `am_expire` needs an `id`, the Jira dedup still holds).

## Pages and endpoints

| Path | Method | Purpose |
| :--- | :--- | :--- |
| `/approvals` | GET | What waits for a decision, and what was decided. |
| `/approvals/<id>` | GET | One approval: the step, what follows it, the alert, what ran so far. |
| `/approvals/<id>/approve`, `/reject` | POST | Decide. Form fields `note`, and `token` when a webhook token is set. |
| `/incidents` | GET | Every incident, newest first. |
| `/incidents/<id>` | GET | One incident: alert, ticket, silences, approvals, timeline, **Resolve**. |
| `/incidents/<id>/resolve` | POST | Close it. Form field `reason`. |

The pages are plain HTML; add `?format=json` (or `Accept: application/json`) for
the same data as JSON. A POST from a browser form redirects back to the page;
a JSON POST gets the record back. `409` means the approval is no longer
pending, `404` that the id is unknown.

**Protect them.** Whoever can reach these pages can approve a restart. Put the
handler behind a login (an ingress with basic auth or an auth proxy: the
Kapitan component's `auth.basic` class does it), or set the webhook token,
which the decision forms then ask for. The handler refuses a POST whose
`Origin` or `Referer` is another site, so a page elsewhere cannot ride on a
logged-in browser.

## Metrics

| Metric | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `alert_handler_incidents` | gauge | `state` | Incidents by state: `open`, `alert_resolved`, `closed`. |
| `alert_handler_approvals_pending` | gauge | | Steps waiting for a person. |
| `alert_handler_approval_decisions_total` | counter | `decision` | `approved`, `rejected`, `expired`, `cancelled`. |

`alert_handler_actions_total` counts a paused step as
`result="awaiting_approval"`. An alert on `alert_handler_approvals_pending > 0`
for longer than it should take a person to look is a good one to have.

## Without Jira

Everything but the `jira_*` actions works without a Jira: silences,
mitigations, approvals, incidents and closing them on `/incidents`. A
`jira_create` in a rule then fails with `jira is not configured`, and the
chain stops there unless it has `continue_on_error: true`. The monitor-lab
deployment runs this way.

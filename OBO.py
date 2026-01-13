OBO_credential = {
    # SD-JWT VC type (credential type)
    "vct": "urn:ai-agent:obo:0002",
    "name": "OnBehalfOfDelegation",
    "description": "Delegation attestation enabling one agent (delegate) to request actions on behalf of a principal under explicit constraints.",

    # Standard-ish JWT claims (still fine in SD-JWT)
    "iss": "",                 # DID of delegating agent (issuer/actor delegator)
    "sub": "",                 # DID of delegate agent (who receives the delegation)
    "aud": "",                 # expected verifier / gateway / service identifier
    "iat": 0,
    "exp": 0,
    "jti": "",                 # unique id for replay protection / allow-list / deny-list

    # OBO semantics: principal (subject-of-action) vs actor (delegate)
    "obo": {
        "principal": {
            "id": "",          # user/principal identifier (could be DID, UUID, email hash)
            "type": "user",    # user|service|org|tenant
            #"tenant": "",      # optional tenancy boundary
        },
        "actor": {
            "id": "",          # usually same as sub, but explicit for clarity
            "type": "agent",
        },
        "delegator": {
            "id": "",          # usually same as iss, but explicit for audits
            "type": "agent",
        },
        #"purpose": "",         # human-readable intent: "schedule_meeting", "book_travel"
        "task_id": "",         # links to an orchestration task
        #"trace_id": "",        # distributed tracing id
        #"policy_ref": "",      # optional policy version/hash that governed issuance
    },

    # What actions are authorized
    "authorization": {
        "actions": [
            # examples:
            # "calendar.create_event",
            # "calendar.update_event",
            # "calendar.read_freebusy",
        ],
        "resources": [
            # structured resource selectors (ABAC-friendly)
            # {"type": "google_calendar", "id": "primary"},
            # {"type": "calendar", "id": "team", "constraints": {"domain": "example.com"}}
        ],
        "scope": "",            # optional legacy string scope
    },

    # Constraints (your earlier "constraint" becomes a structured object)
    "constraints": {
        #"time_window": {
        #    "start": "",        # ISO8601
        #    "end": "",          # ISO8601
        #    "timezone": "Europe/Paris",
        #},
        "limits": {
            "max_calls": 1,                 # max number of executions allowed
            "max_events": 1,                # calendar specific
            "max_duration_minutes": 60,
            "max_attendees": 10,
        },
        "data": {
            "allow_external_attendees": False,
            #"attendee_domain_allowlist": [], # e.g. ["example.com"]
            "title_max_len": 120,
            "description_max_len": 2000,
        },
        "risk_controls": {
            "require_human_approval_if": [
                # e.g. {"field": "attendees.external_count", "op": ">", "value": 0}
            ],
            "deny_if": [
                # e.g. {"field": "start_in_minutes", "op": "<", "value": 5}
            ]
        },
    },

    # Delegation chaining rules
    "delegation": {
        "redelegation": "deny",     # deny|allow|attenuate_only
        "max_hops": 0,              # 0 means cannot redelegate
        "parent_jti": "",           # if this credential is derived from another
        "attenuation_rules": [
            # Optional: what can be reduced when redelegating
            # "actions", "resources", "time_window", "limits"
        ],
    }
}

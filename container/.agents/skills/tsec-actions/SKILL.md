---
name: tsec-actions
description: Submit a flag for a challenge in a tsec CTF or automated security exercise
---

## Usage

* Call the API with `curl`. `TSEC_SERVER_HOST` and `TSEC_AGENT_TOKEN` are already in the environment.
* Flags use the `flag{...}` form.

Submit a flag:

```bash
curl -X POST "http://${TSEC_SERVER_HOST}/api/submit" \
  -H "Agent-Token: ${TSEC_AGENT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"code": "<challenge_code>", "flag": "<flag>"}'
```

## Rules

- Submit a flag only when confidence is high. Do not treat this as a brute-force endpoint.
- Trust the API response. Do not assume the submission succeeded.

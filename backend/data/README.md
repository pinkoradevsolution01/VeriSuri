# Permissioned training data contract

Never add user submissions, OTPs, account numbers, or raw private conversations without explicit lawful permission and privacy review.

The local training CSV must be UTF-8 and contain:

```text
text,label,language,source,consent_reference
"Your account is blocked...",1,en,permissioned-research,consent-001
"Salamat sa inyong order",0,fil,permissioned-research,consent-002
```

- `label`: `1` means scam/fraud signal; `0` means legitimate.
- `language`: `en`, `fil`, or `taglish` enables fairness checks.
- `source` and `consent_reference` document authorization and auditability.

Run `py backend/train.py backend/data/approved_messages.csv --version verisuri-hybrid-v1` only after data approval. Review the generated metrics before replacing a deployed model.

For a pipeline smoke test only, run `py backend/generate_demo_dataset.py` and train against `backend/data/synthetic_demo_messages.csv`. This synthetic output is intentionally excluded from Git and must never be registered or deployed as a production model.

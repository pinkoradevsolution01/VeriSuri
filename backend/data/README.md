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

## Release-candidate gate

The trainer now rejects synthetic data, duplicate messages, missing consent references, and datasets with fewer than 300 rows. It also requires representation for `en`, `fil`, and `taglish`, with both classes in each language. This is a minimum validation floor, not proof of nationwide accuracy.

Train only after data approval:

```powershell
.\.venv\Scripts\python.exe backend\train.py backend\data\approved_messages.csv --version verisuri-hybrid-v1
.\.venv\Scripts\python.exe backend\evaluate.py backend\models\verisuri_v1.metrics.json
.\.venv\Scripts\python.exe backend\approve_model.py backend\models\verisuri_v1.metrics.json --reviewer "reviewer-id"
.\.venv\Scripts\python.exe backend\register_model.py backend\models\verisuri_v1.metrics.json
```

The evaluator blocks release candidates unless overall and per-language held-out precision, recall, F1, and false-positive rate meet the declared gates. The model will not load in VeriSuri until its metrics are marked `approved`.

For a pipeline smoke test only, run `py backend/generate_demo_dataset.py` and train against `backend/data/synthetic_demo_messages.csv`. This synthetic output is intentionally excluded from Git and must never be registered or deployed as a production model.

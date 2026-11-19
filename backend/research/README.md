# Research baseline workflow

This directory is for licensed international data and machine- or human-translated derivatives. It is **not** a production dataset.

1. Obtain the source under a licence that allows derivative ML use. Record the exact source URL and SPDX licence in every row.
2. Translate only into `synthetic_tagalog` or `synthetic_taglish`; preserve the original text in `source_text` for audit.
3. Run `python backend/research/train_baseline.py path/to/research.csv --version research-v1`.

Required CSV columns:

```text
text,label,language,source,source_url,license,translation_type,source_text
```

`label` is `0` legitimate or `1` scam. `translation_type` is `original`, `human_translation`, or `machine_translation`.

The generated metrics always state `research_only` and `production_eligible: false`. The production trainer and model loader reject this data and its artifacts. Only consented, naturally occurring Philippine examples can pass `backend/train.py` and release approval.

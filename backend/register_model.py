"""Register evaluated model metadata in Supabase; never upload model artifacts through this script."""
import argparse, asyncio, json
from pathlib import Path
from backend.app.services.supabase import SupabaseRepository

async def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("metrics", type=Path); parser.add_argument("--artifact-uri", default=None); args = parser.parse_args()
    metrics = json.loads(args.metrics.read_text(encoding="utf-8")); repository = SupabaseRepository()
    if not repository.enabled: raise SystemExit("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required.")
    import httpx
    headers = {"apikey": repository.key or "", "Authorization": f"Bearer {repository.key or ''}", "Content-Type": "application/json", "Prefer": "resolution=merge-duplicates"}
    payload = {"version": metrics["version"], "metrics": metrics, "artifact_uri": args.artifact_uri}
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(f"{repository.url}/rest/v1/model_versions", headers=headers, json=payload); response.raise_for_status()
    print(f"Registered {metrics['version']}")

if __name__ == "__main__": asyncio.run(main())

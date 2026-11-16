"""Validate a configured VeriSuri Before You Pay deployment.

Use a real, moderator-confirmed record created through the app. This script
never inserts records or treats test data as community intelligence.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import httpx


async def get_json(client: httpx.AsyncClient, url: str, *, payload: dict | None = None) -> dict:
    response = await (client.post(url, json=payload) if payload else client.get(url))
    response.raise_for_status()
    return response.json()


async def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Before You Pay integrations against a live API.")
    parser.add_argument("--identifier", required=True, help="Identifier from a moderator-confirmed report")
    parser.add_argument("--entity-type", choices=["gcash", "maya", "bank", "phone", "url"], required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000/api/v1")
    parser.add_argument("--skip-web-risk", action="store_true", help="Skip the official Google Web Risk test URL")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    async with httpx.AsyncClient(timeout=12) as client:
        health = await get_json(client, f"{base}/health")
        print("Health:", health)
        if not health.get("supabase_report_matching_configured"):
            print("FAIL: Supabase report matching is not configured.", file=sys.stderr)
            return 1

        lookup = await get_json(client, f"{base}/reports/lookup", payload={"identifier": args.identifier, "entity_type": args.entity_type})
        print("Report lookup:", lookup)
        if lookup.get("source") != "supabase-report-matching" or lookup.get("score", 0) < 62:
            print("FAIL: the supplied identifier did not match a confirmed moderated record.", file=sys.stderr)
            return 1

        if not args.skip_web_risk:
            if not health.get("web_risk_configured"):
                print("FAIL: GOOGLE_WEB_RISK_API_KEY is not configured.", file=sys.stderr)
                return 1
            test_url = "http://testsafebrowsing.appspot.com/s/malware.html"
            link = await get_json(client, f"{base}/analyze/link", payload={"url": test_url})
            print("Web Risk lookup:", link)
            if link.get("source") != "google-web-risk+url-rules" or not any("Google Web Risk matched" in signal for signal in link.get("signals", [])):
                print("FAIL: Web Risk did not return the expected test-list match.", file=sys.stderr)
                return 1

    print("PASS: Web Risk and confirmed-report matching are working.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

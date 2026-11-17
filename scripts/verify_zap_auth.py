from __future__ import annotations

import argparse
import json
import time
import urllib.parse

import zapv2

from app.adapters.zap_adapter import ZapAdapter
from app.auth_session import authenticate, get_auth_profile
from app.config import settings


def _spider_urls(client, target: str, auth_ref: str, auth: bool) -> int:
    context_name = f"verify-{int(time.time() * 1000)}"
    context_id = client.context.new_context(context_name)
    cookie_rule = ""
    try:
        host = urllib.parse.urlparse(target).hostname or target
        client.context.include_in_context(
            context_name,
            rf"https?://{host}(:\d+)?(/.*)?",
        )
        client.context.set_context_in_scope(context_name, True)
        profile = get_auth_profile(auth_ref)
        for path in profile.safe_path_denylist:
            client.context.exclude_from_context(
                context_name,
                rf"https?://{host}(:\d+)?/{str(path).lstrip('/')}(?:\?.*)?$",
            )
        client.spider.set_option_process_form(False)
        auth_result = authenticate(auth_ref) if auth else None
        if auth_result and auth_result.authenticated:
            cookie_rule = ZapAdapter._install_cookie_auth(
                client,
                target,
                auth_result.cookie_header,
            )
        scan_id = client.spider.scan(
            target,
            recurse=True,
            contextname=context_name,
        )
        deadline = time.time() + 300
        while time.time() < deadline:
            if int(client.spider.status(scan_id)) >= 100:
                break
            time.sleep(2)
        else:
            client.spider.stop_all_scans()
            raise TimeoutError("spider timeout")
        return len(client.context.urls(context_name))
    finally:
        if cookie_rule:
            try:
                client.replacer.remove_rule(cookie_rule)
            except Exception:
                pass
        client.context.remove_context(context_name)


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare ZAP URL coverage with and without login.")
    parser.add_argument("--target", default="http://dvwa")
    parser.add_argument("--auth-ref", default="local-dvwa")
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    client = zapv2.ZAPv2(
        proxies={"http": settings.zap_url, "https": settings.zap_url},
        apikey=settings.zap_api_key,
    )
    client.core.new_session(apikey=settings.zap_api_key)
    unauthenticated = _spider_urls(client, args.target, args.auth_ref, False)
    client.core.new_session(apikey=settings.zap_api_key)
    authenticated = _spider_urls(client, args.target, args.auth_ref, True)
    result = {
        "target": args.target,
        "unauthenticated_url_count": unauthenticated,
        "authenticated_url_count": authenticated,
        "passed": authenticated > unauthenticated and authenticated >= 8,
    }
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    print(text)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

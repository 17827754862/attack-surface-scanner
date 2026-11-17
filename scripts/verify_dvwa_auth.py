from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import httpx


DEFAULT_PAGES = [
    "/index.php",
    "/instructions.php",
    "/vulnerabilities/sqli/",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/xss_s/",
    "/vulnerabilities/exec/",
    "/vulnerabilities/fi/",
    "/vulnerabilities/upload/",
    "/vulnerabilities/csrf/",
    "/vulnerabilities/brute/",
]


def verify(base_url: str, username: str, password: str) -> dict:
    cookies: dict[str, str] = {}
    with httpx.Client(
        base_url=base_url.rstrip("/"),
        follow_redirects=True,
        timeout=20,
    ) as client:
        setup = client.get("/setup.php")
        setup.raise_for_status()
        setup_token = re.search(
            r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)",
            setup.text,
            flags=re.IGNORECASE,
        )
        if "Create / Reset Database" in setup.text:
            reset = client.post(
                "/setup.php",
                data={
                    "create_db": "Create / Reset Database",
                    "user_token": setup_token.group(1) if setup_token else "",
                },
            )
            reset.raise_for_status()
        login = client.get("/login.php")
        login.raise_for_status()
        token_match = re.search(
            r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)",
            login.text,
            flags=re.IGNORECASE,
        )
        token = token_match.group(1) if token_match else ""
        response = client.post(
            "/login.php",
            data={
                "username": username,
                "password": password,
                "Login": "Login",
                "user_token": token,
            },
        )
        response.raise_for_status()
        logged_in = "logout" in response.text.lower()
        pages = []
        for path in DEFAULT_PAGES:
            page = client.get(path)
            pages.append(
                {
                    "path": path,
                    "status_code": page.status_code,
                    "authenticated": "logout" in page.text.lower(),
                    "bytes": len(page.content),
                }
            )
    return {
        "base_url": base_url,
        "logged_in": logged_in,
        "authenticated_pages": sum(
            1
            for page in pages
            if page["status_code"] < 400 and page["authenticated"]
        ),
        "pages": pages,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify authenticated DVWA coverage.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8081")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="password")
    parser.add_argument("--output", default="")
    parser.add_argument("--minimum-pages", type=int, default=8)
    args = parser.parse_args()
    result = verify(args.base_url, args.username, args.password)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["logged_in"]:
        return 2
    if result["authenticated_pages"] < args.minimum_pages:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

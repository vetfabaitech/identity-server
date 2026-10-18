"""GitHub OAuth app sign-in. Request shapes ported from the IDE's log-in/backend/app/services/github_oauth.py."""

from typing import Any
from urllib.parse import urlencode

import httpx

from identity.config import Settings
from identity.oauth.base import TIMEOUT_SECONDS, OAuthError, Profile, ProviderName

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"  # noqa: S105  # a URL, not a secret
USER_URL = "https://api.github.com/user"
EMAILS_URL = "https://api.github.com/user/emails"
# read:user for the profile; user:email because a private primary email only appears on /user/emails.
SCOPES = "read:user user:email"
API_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


def _verified_email(user: dict[str, Any], emails: list[dict[str, Any]]) -> str | None:
    verified = [e for e in emails if isinstance(e, dict) and e.get("verified") is True and e.get("email")]
    public = user.get("email")
    if public and any(e["email"].lower() == str(public).lower() for e in verified):
        return str(public)
    primary = next((e for e in verified if e.get("primary") is True), None)
    return str(primary["email"]) if primary else None


class GitHub:
    name: ProviderName = "github"
    label = "GitHub"

    def configured(self, settings: Settings) -> bool:
        return bool(settings.github_client_id and settings.github_client_secret)

    def authorize_url(self, settings: Settings, state: str) -> str:
        query = {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.oauth_redirect_uri(self.name),
            "scope": SCOPES,
            "state": state,
            "allow_signup": "true",
        }
        return f"{AUTHORIZE_URL}?{urlencode(query)}"

    async def fetch_profile(self, settings: Settings, code: str, client: httpx.AsyncClient | None = None) -> Profile:
        owned = client is None
        http = client or httpx.AsyncClient(timeout=TIMEOUT_SECONDS)
        try:
            return await self._fetch(settings, code, http)
        except httpx.HTTPError as exc:
            raise OAuthError("provider", type(exc).__name__) from exc
        except (ValueError, KeyError, TypeError) as exc:
            raise OAuthError("provider", "unexpected response") from exc
        finally:
            if owned:
                await http.aclose()

    async def _fetch(self, settings: Settings, code: str, http: httpx.AsyncClient) -> Profile:
        secret = settings.github_client_secret.get_secret_value() if settings.github_client_secret else ""
        token_response = await http.post(
            TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.github_client_id,
                "client_secret": secret,
                "code": code,
                "redirect_uri": settings.oauth_redirect_uri(self.name),
            },
        )
        body = token_response.json() if token_response.status_code == 200 else {}
        token = body.get("access_token") if isinstance(body, dict) else None
        if not token:
            raise OAuthError("provider", f"token exchange failed ({token_response.status_code})")
        headers = {**API_HEADERS, "Authorization": f"Bearer {token}"}
        user_response = await http.get(USER_URL, headers=headers)
        if user_response.status_code != 200:
            raise OAuthError("provider", f"profile failed ({user_response.status_code})")
        user = user_response.json()
        emails_response = await http.get(EMAILS_URL, headers=headers)
        emails = emails_response.json() if emails_response.status_code == 200 else []
        verified = _verified_email(user, emails if isinstance(emails, list) else [])
        claimed = verified or user.get("email") or None
        return Profile(
            provider=self.name,
            provider_user_id=str(user["id"]),
            email=str(claimed) if claimed else None,
            email_verified=verified is not None,
            display_name=str(user.get("name") or user["login"]),
        )

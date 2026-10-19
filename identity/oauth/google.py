"""Google sign-in (OpenID Connect userinfo v3). Request shapes follow the IDE's log-in/backend google_oauth.py."""

from urllib.parse import urlencode

import httpx

from identity.config import Settings
from identity.oauth.base import TIMEOUT_SECONDS, OAuthError, Profile, ProviderName

AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105  # a URL, not a secret
USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
SCOPES = "openid email profile"


class Google:
    name: ProviderName = "google"
    label = "Google"

    def configured(self, settings: Settings) -> bool:
        return bool(settings.google_client_id and settings.google_client_secret)

    def authorize_url(self, settings: Settings, state: str) -> str:
        query = {
            "client_id": settings.google_client_id,
            "redirect_uri": settings.oauth_redirect_uri(self.name),
            "response_type": "code",
            "scope": SCOPES,
            "state": state,
            "prompt": "select_account",
        }
        return f"{AUTHORIZE_URL}?{urlencode(query)}"

    async def fetch_profile(self, settings: Settings, code: str, client: httpx.AsyncClient | None = None) -> Profile:
        owned = client is None
        http = client or httpx.AsyncClient(timeout=TIMEOUT_SECONDS)
        try:
            return await self._fetch(settings, code, http)
        except httpx.HTTPError as exc:
            raise OAuthError("provider", type(exc).__name__) from exc
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise OAuthError("provider", "unexpected response") from exc
        finally:
            if owned:
                await http.aclose()

    async def _fetch(self, settings: Settings, code: str, http: httpx.AsyncClient) -> Profile:
        secret = settings.google_client_secret.get_secret_value() if settings.google_client_secret else ""
        token_response = await http.post(
            TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.google_client_id,
                "client_secret": secret,
                "code": code,
                "redirect_uri": settings.oauth_redirect_uri(self.name),
                "grant_type": "authorization_code",
            },
        )
        body = token_response.json() if token_response.content else {}
        token = body.get("access_token") if isinstance(body, dict) and token_response.status_code == 200 else None
        if not token:
            code = str(body.get("error", ""))[:64] if isinstance(body, dict) else ""
            raise OAuthError("provider", f"token exchange failed ({token_response.status_code} {code})".rstrip())
        info_response = await http.get(USERINFO_URL, headers={"Authorization": f"Bearer {token}"})
        if info_response.status_code != 200:
            raise OAuthError("provider", f"userinfo failed ({info_response.status_code})")
        info = info_response.json()
        email = info.get("email") or None
        verified = info.get("email_verified") in (True, "true")
        name = info.get("name") or (str(email).split("@")[0] if email else "Google user")
        return Profile(
            provider=self.name,
            provider_user_id=str(info["sub"]),
            email=str(email) if email else None,
            email_verified=bool(email) and verified,
            display_name=str(name),
        )

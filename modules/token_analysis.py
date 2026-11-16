import base64
import json
import re

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _b64decode(segment):
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def decode_jwt(token):
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64decode(parts[0]))
        payload = json.loads(_b64decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    signature = parts[2] if len(parts) > 2 else ""
    return {"header": header, "payload": payload, "signature_present": bool(signature)}


def analyze_jwt(token, report=None):
    decoded = decode_jwt(token)
    if not decoded:
        return None

    header, payload = decoded["header"], decoded["payload"]
    alg = header.get("alg", "")

    if report:
        report.add_finding("Token Analysis", f"JWT decoded (alg={alg})",
                            f"header={header} payload={payload}", "INFO")

        if alg.lower() == "none":
            report.add_finding("Token Analysis", "JWT uses alg=none",
                                "Server may accept unsigned tokens, allowing claim "
                                "tampering without a valid signature", "CRITICAL",
                                vuln_id="jwt_alg_none")
        elif alg.upper().startswith("HS") and not decoded["signature_present"]:
            report.add_finding("Token Analysis", "JWT missing signature",
                                "Token has no signature segment", "HIGH")
        elif alg.upper().startswith("HS"):
            report.add_finding("Token Analysis", f"JWT uses symmetric algorithm {alg}",
                                "Worth testing against common/weak secrets offline "
                                "(e.g. with hashcat mode 16500 or jwt_tool)", "MEDIUM",
                                vuln_id="jwt_weak_secret_suspected")

        exp = payload.get("exp")
        if not exp:
            report.add_finding("Token Analysis", "JWT has no expiration claim",
                                "Tokens without 'exp' may remain valid indefinitely", "LOW")

    return decoded


def find_jwts_in_text(text):
    return JWT_PATTERN.findall(text or "")


def decode_ntlm_type2(base64_blob):
    try:
        data = base64.b64decode(base64_blob)
    except Exception:
        return None
    if data[:8] != b"NTLMSSP\x00" or len(data) < 32:
        return None

    target_name_len = int.from_bytes(data[12:14], "little")
    target_name_off = int.from_bytes(data[16:20], "little")
    target_name = data[target_name_off:target_name_off + target_name_len].decode("utf-16-le", errors="ignore")

    return {"target_name": target_name}


def check_ntlm_auth(base_url, report=None):
    try:
        resp = requests.get(base_url, timeout=6, verify=False)
    except requests.RequestException:
        return None
    auth_header = resp.headers.get("WWW-Authenticate", "")
    if "NTLM" not in auth_header and "Negotiate" not in auth_header:
        return None

    try:
        negotiate_headers = {"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="}
        resp2 = requests.get(base_url, headers=negotiate_headers, timeout=6, verify=False)
        challenge_header = resp2.headers.get("WWW-Authenticate", "")
        match = re.search(r"NTLM (\S+)", challenge_header)
        if match:
            info = decode_ntlm_type2(match.group(1))
            if info and report:
                report.add_finding("Token Analysis", "NTLM authentication exposes internal hostname",
                                    f"Target/domain name disclosed: {info['target_name']}", "LOW",
                                    vuln_id="ntlm_info_disclosure")
            return info
    except requests.RequestException:
        pass
    if report:
        report.add_finding("Token Analysis", "NTLM/Negotiate authentication offered",
                            f"WWW-Authenticate: {auth_header}", "INFO")
    return None


def check_oauth_saml(base_url, report=None):
    findings = {}
    oidc_config = f"{base_url}/.well-known/openid-configuration"
    try:
        resp = requests.get(oidc_config, timeout=6, verify=False)
        if resp.status_code == 200:
            findings["openid_configuration"] = resp.json()
            if report:
                report.add_finding("Token Analysis", "OpenID Connect discovery document exposed",
                                    oidc_config, "INFO")
    except (requests.RequestException, ValueError):
        pass

    for path in ("oauth/authorize", "oauth2/authorize", "saml/login", "saml2/login", "sso/saml"):
        try:
            resp = requests.get(f"{base_url}/{path}", timeout=5, verify=False, allow_redirects=False)
            if resp.status_code < 500:
                findings[path] = resp.status_code
                if report and resp.status_code in (200, 302, 401, 403):
                    kind = "SAML" if "saml" in path else "OAuth"
                    report.add_finding("Token Analysis", f"{kind} endpoint found: /{path}",
                                        f"HTTP {resp.status_code}", "INFO")
        except requests.RequestException:
            continue
    return findings

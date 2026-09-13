import base64
import hashlib
import hmac
import re
import time
from urllib.parse import parse_qsl


class InvalidWebhook(ValueError):
    pass


def verify_stripe_signature(
    raw_body: bytes,
    signature_header: str,
    secret: str,
    *,
    now: int | None = None,
    tolerance_seconds: int = 300,
) -> None:
    if not raw_body or len(raw_body) > 65_536:
        raise InvalidWebhook("Stripe body is empty or too large")
    fields: dict[str, list[str]] = {}
    for item in signature_header.split(","):
        key, separator, value = item.partition("=")
        if not separator or not key or not value:
            raise InvalidWebhook("Malformed Stripe signature")
        fields.setdefault(key, []).append(value)
    try:
        timestamp = int(fields["t"][0])
    except (KeyError, ValueError, IndexError) as exc:
        raise InvalidWebhook("Missing Stripe signature timestamp") from exc
    current = int(time.time()) if now is None else now
    if timestamp < 0 or abs(current - timestamp) > tolerance_seconds:
        raise InvalidWebhook("Stripe signature timestamp is outside tolerance")
    signed = str(timestamp).encode() + b"." + raw_body
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    signatures = fields.get("v1", [])
    if not signatures or not any(hmac.compare_digest(expected, value) for value in signatures):
        raise InvalidWebhook("Stripe signature mismatch")


def parse_twilio_form(raw_body: bytes) -> dict[str, str]:
    if not raw_body or len(raw_body) > 65_536:
        raise InvalidWebhook("Twilio body is empty or too large")
    try:
        text = raw_body.decode("utf-8")
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True, max_num_fields=64)
    except (UnicodeDecodeError, ValueError) as exc:
        raise InvalidWebhook("Malformed Twilio form body") from exc
    names = [key for key, _ in pairs]
    if len(names) != len(set(names)):
        raise InvalidWebhook("Duplicate Twilio form key")
    return dict(pairs)


def verify_twilio_signature(url: str, params: dict[str, str], signature_header: str, token: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", signature_header):
        raise InvalidWebhook("Malformed Twilio signature")
    canonical = url + "".join(key + value for key, value in sorted(params.items()))
    digest = hmac.new(token.encode(), canonical.encode(), hashlib.sha1).digest()
    expected = base64.b64encode(digest).decode()
    if not hmac.compare_digest(expected, signature_header):
        raise InvalidWebhook("Twilio signature mismatch")

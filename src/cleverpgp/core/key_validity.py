from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cleverpgp.core.errors import ValidationError

DEFAULT_KEY_VALIDITY_DAYS = 730


def expiration_from_validity_days(
    created_at: datetime,
    validity_days: int | None,
) -> str | None:
    """Return a normalized UTC expiry time or ``None`` for no expiry."""

    if validity_days is None:
        return None
    days = int(validity_days)
    if not 30 <= days <= 36500:
        raise ValidationError("Недопустимый срок действия цифрового ключа.")
    created = created_at.astimezone(UTC)
    return (created + timedelta(days=days)).isoformat()


def normalize_expiration(value: object) -> str | None:
    if value is None or value == "":
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError("Некорректный срок действия цифрового ключа.") from error
    if parsed.tzinfo is None:
        raise ValidationError("Срок действия цифрового ключа должен быть указан в UTC.")
    return parsed.astimezone(UTC).isoformat()


def key_is_expired(expires_at: str | None, *, now: datetime | None = None) -> bool:
    normalized = normalize_expiration(expires_at)
    if normalized is None:
        return False
    current = (now or datetime.now(UTC)).astimezone(UTC)
    return datetime.fromisoformat(normalized) <= current


__all__ = [
    "DEFAULT_KEY_VALIDITY_DAYS",
    "expiration_from_validity_days",
    "key_is_expired",
    "normalize_expiration",
]

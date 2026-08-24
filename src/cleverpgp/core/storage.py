from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from cleverpgp.core.errors import ContactExistsError, ProfileExistsError
from cleverpgp.core.models import (
    BiometricProfile,
    Contact,
    CryptographicIdentity,
    Profile,
    UserKey,
    UnlockMode,
)

SCHEMA_VERSION = 4


class ProfileRepository:
    """SQLite storage for the single local MVP profile."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS profile (
                    singleton_slot INTEGER PRIMARY KEY CHECK (singleton_slot = 1),
                    profile_id TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    unlock_mode TEXT NOT NULL,
                    kdf_salt BLOB NOT NULL,
                    kdf_opslimit INTEGER NOT NULL,
                    kdf_memlimit INTEGER NOT NULL,
                    encrypted_master_key BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS biometric_profile (
                    singleton_slot INTEGER PRIMARY KEY CHECK (singleton_slot = 1),
                    profile_id TEXT NOT NULL,
                    protected_biometric_key BLOB NOT NULL,
                    encrypted_template BLOB NOT NULL,
                    encrypted_master_key BLOB NOT NULL,
                    model_id TEXT NOT NULL,
                    model_sha256 TEXT NOT NULL,
                    match_threshold REAL NOT NULL,
                    enrolled_at TEXT NOT NULL,
                    FOREIGN KEY(profile_id) REFERENCES profile(profile_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS cryptographic_identity (
                    singleton_slot INTEGER PRIMARY KEY CHECK (singleton_slot = 1),
                    profile_id TEXT NOT NULL UNIQUE,
                    encryption_public_key BLOB NOT NULL,
                    signing_public_key BLOB NOT NULL,
                    encrypted_encryption_private_key BLOB NOT NULL,
                    encrypted_signing_seed BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(profile_id) REFERENCES profile(profile_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS contact (
                    contact_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    fingerprint TEXT NOT NULL UNIQUE,
                    encryption_public_key BLOB NOT NULL UNIQUE,
                    signing_public_key BLOB NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS user_key (
                    key_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    fingerprint TEXT NOT NULL UNIQUE,
                    encryption_public_key BLOB NOT NULL UNIQUE,
                    signing_public_key BLOB NOT NULL UNIQUE,
                    kdf_salt BLOB NOT NULL,
                    kdf_opslimit INTEGER NOT NULL,
                    kdf_memlimit INTEGER NOT NULL,
                    encrypted_private_bundle BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            connection.execute(
                """
                INSERT INTO metadata(key, value) VALUES('schema_version', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(SCHEMA_VERSION),),
            )

    def has_profile(self) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM profile WHERE singleton_slot = 1"
            ).fetchone()
        return row is not None

    def get_setting(self, key: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = ?", (key,)
            ).fetchone()
        return None if row is None else str(row["value"])

    def set_setting(self, key: str, value: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO metadata(key, value) VALUES(?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def save_profile(self, profile: Profile) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO profile(
                        singleton_slot, profile_id, display_name, unlock_mode,
                        kdf_salt, kdf_opslimit, kdf_memlimit,
                        encrypted_master_key, created_at
                    ) VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        profile.profile_id,
                        profile.display_name,
                        profile.unlock_mode.value,
                        profile.kdf_salt,
                        profile.kdf_opslimit,
                        profile.kdf_memlimit,
                        profile.encrypted_master_key,
                        profile.created_at,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise ProfileExistsError("Локальный профиль уже существует.") from error

    def get_profile(self) -> Profile | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT profile_id, display_name, unlock_mode, kdf_salt,
                       kdf_opslimit, kdf_memlimit, encrypted_master_key,
                       created_at
                FROM profile
                WHERE singleton_slot = 1
                """
            ).fetchone()

        if row is None:
            return None

        return Profile(
            profile_id=row["profile_id"],
            display_name=row["display_name"],
            unlock_mode=UnlockMode(row["unlock_mode"]),
            kdf_salt=bytes(row["kdf_salt"]),
            kdf_opslimit=int(row["kdf_opslimit"]),
            kdf_memlimit=int(row["kdf_memlimit"]),
            encrypted_master_key=bytes(row["encrypted_master_key"]),
            created_at=row["created_at"],
        )

    def update_unlock_mode(self, unlock_mode: UnlockMode) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE profile SET unlock_mode = ? WHERE singleton_slot = 1",
                (unlock_mode.value,),
            )
        if cursor.rowcount != 1:
            raise ValueError("Profile does not exist")

    def update_password_slot(
        self,
        *,
        profile_id: str,
        expected_encrypted_master_key: bytes,
        kdf_salt: bytes,
        kdf_opslimit: int,
        kdf_memlimit: int,
        encrypted_master_key: bytes,
    ) -> None:
        """Atomically replace the password wrapper for the current master key.

        The previous encrypted value is part of the update predicate. This
        prevents a second Clever PGP process from silently overwriting a newer
        password slot with stale profile data.
        """

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE profile
                SET kdf_salt = ?, kdf_opslimit = ?, kdf_memlimit = ?,
                    encrypted_master_key = ?
                WHERE singleton_slot = 1
                  AND profile_id = ?
                  AND encrypted_master_key = ?
                """,
                (
                    kdf_salt,
                    kdf_opslimit,
                    kdf_memlimit,
                    encrypted_master_key,
                    profile_id,
                    expected_encrypted_master_key,
                ),
            )
        if cursor.rowcount != 1:
            raise ValueError("Profile password slot changed concurrently")

    def has_biometric_profile(self) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM biometric_profile WHERE singleton_slot = 1"
            ).fetchone()
        return row is not None

    def save_biometric_profile(self, profile: BiometricProfile) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO biometric_profile(
                    singleton_slot, profile_id, protected_biometric_key,
                    encrypted_template, encrypted_master_key, model_id,
                    model_sha256, match_threshold, enrolled_at
                ) VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(singleton_slot) DO UPDATE SET
                    profile_id = excluded.profile_id,
                    protected_biometric_key = excluded.protected_biometric_key,
                    encrypted_template = excluded.encrypted_template,
                    encrypted_master_key = excluded.encrypted_master_key,
                    model_id = excluded.model_id,
                    model_sha256 = excluded.model_sha256,
                    match_threshold = excluded.match_threshold,
                    enrolled_at = excluded.enrolled_at
                """,
                (
                    profile.profile_id,
                    profile.protected_biometric_key,
                    profile.encrypted_template,
                    profile.encrypted_master_key,
                    profile.model_id,
                    profile.model_sha256,
                    profile.match_threshold,
                    profile.enrolled_at,
                ),
            )

    def get_biometric_profile(self) -> BiometricProfile | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT profile_id, protected_biometric_key, encrypted_template,
                       encrypted_master_key, model_id, model_sha256,
                       match_threshold, enrolled_at
                FROM biometric_profile
                WHERE singleton_slot = 1
                """
            ).fetchone()
        if row is None:
            return None
        return BiometricProfile(
            profile_id=row["profile_id"],
            protected_biometric_key=bytes(row["protected_biometric_key"]),
            encrypted_template=bytes(row["encrypted_template"]),
            encrypted_master_key=bytes(row["encrypted_master_key"]),
            model_id=row["model_id"],
            model_sha256=row["model_sha256"],
            match_threshold=float(row["match_threshold"]),
            enrolled_at=row["enrolled_at"],
        )

    def save_cryptographic_identity(
        self,
        identity: CryptographicIdentity,
    ) -> bool:
        """Store the first local identity and never replace it implicitly."""

        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO cryptographic_identity(
                    singleton_slot, profile_id, encryption_public_key,
                    signing_public_key, encrypted_encryption_private_key,
                    encrypted_signing_seed, created_at
                ) VALUES(1, ?, ?, ?, ?, ?, ?)
                """,
                (
                    identity.profile_id,
                    identity.encryption_public_key,
                    identity.signing_public_key,
                    identity.encrypted_encryption_private_key,
                    identity.encrypted_signing_seed,
                    identity.created_at,
                ),
            )
        return cursor.rowcount == 1

    def get_cryptographic_identity(self) -> CryptographicIdentity | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT profile_id, encryption_public_key, signing_public_key,
                       encrypted_encryption_private_key,
                       encrypted_signing_seed, created_at
                FROM cryptographic_identity
                WHERE singleton_slot = 1
                """
            ).fetchone()
        if row is None:
            return None
        return CryptographicIdentity(
            profile_id=row["profile_id"],
            encryption_public_key=bytes(row["encryption_public_key"]),
            signing_public_key=bytes(row["signing_public_key"]),
            encrypted_encryption_private_key=bytes(
                row["encrypted_encryption_private_key"]
            ),
            encrypted_signing_seed=bytes(row["encrypted_signing_seed"]),
            created_at=row["created_at"],
        )

    def save_contact(self, contact: Contact) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO contact(
                        contact_id, display_name, fingerprint,
                        encryption_public_key, signing_public_key, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?)
                    """,
                    (
                        contact.contact_id,
                        contact.display_name,
                        contact.fingerprint,
                        contact.encryption_public_key,
                        contact.signing_public_key,
                        contact.created_at,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise ContactExistsError(
                "Контакт с таким открытым ключом уже существует."
            ) from error

    def save_user_key(self, key: UserKey) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO user_key(
                        key_id, display_name, fingerprint,
                        encryption_public_key, signing_public_key,
                        kdf_salt, kdf_opslimit, kdf_memlimit,
                        encrypted_private_bundle, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key.key_id,
                        key.display_name,
                        key.fingerprint,
                        key.encryption_public_key,
                        key.signing_public_key,
                        key.kdf_salt,
                        key.kdf_opslimit,
                        key.kdf_memlimit,
                        key.encrypted_private_bundle,
                        key.created_at,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise ContactExistsError(
                "Такой цифровой ключ уже сохранён в Clever PGP."
            ) from error

    def list_user_keys(self) -> tuple[UserKey, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT key_id, display_name, fingerprint,
                       encryption_public_key, signing_public_key,
                       kdf_salt, kdf_opslimit, kdf_memlimit,
                       encrypted_private_bundle, created_at
                FROM user_key
                ORDER BY display_name COLLATE NOCASE, created_at
                """
            ).fetchall()
        return tuple(self._user_key_from_row(row) for row in rows)

    def get_user_key(self, key_id: str) -> UserKey | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT key_id, display_name, fingerprint,
                       encryption_public_key, signing_public_key,
                       kdf_salt, kdf_opslimit, kdf_memlimit,
                       encrypted_private_bundle, created_at
                FROM user_key WHERE key_id = ?
                """,
                (key_id,),
            ).fetchone()
        return None if row is None else self._user_key_from_row(row)

    def get_user_key_by_fingerprint(self, fingerprint: str) -> UserKey | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT key_id, display_name, fingerprint,
                       encryption_public_key, signing_public_key,
                       kdf_salt, kdf_opslimit, kdf_memlimit,
                       encrypted_private_bundle, created_at
                FROM user_key WHERE fingerprint = ?
                """,
                (fingerprint,),
            ).fetchone()
        return None if row is None else self._user_key_from_row(row)

    def delete_user_key(self, key_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM user_key WHERE key_id = ?",
                (key_id,),
            )
        return cursor.rowcount == 1

    def list_contacts(self) -> tuple[Contact, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT contact_id, display_name, fingerprint,
                       encryption_public_key, signing_public_key, created_at
                FROM contact
                ORDER BY display_name COLLATE NOCASE, fingerprint
                """
            ).fetchall()
        return tuple(
            Contact(
                contact_id=row["contact_id"],
                display_name=row["display_name"],
                fingerprint=row["fingerprint"],
                encryption_public_key=bytes(row["encryption_public_key"]),
                signing_public_key=bytes(row["signing_public_key"]),
                created_at=row["created_at"],
            )
            for row in rows
        )

    def get_contact_by_fingerprint(self, fingerprint: str) -> Contact | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT contact_id, display_name, fingerprint,
                       encryption_public_key, signing_public_key, created_at
                FROM contact
                WHERE fingerprint = ?
                """,
                (fingerprint,),
            ).fetchone()
        if row is None:
            return None
        return Contact(
            contact_id=row["contact_id"],
            display_name=row["display_name"],
            fingerprint=row["fingerprint"],
            encryption_public_key=bytes(row["encryption_public_key"]),
            signing_public_key=bytes(row["signing_public_key"]),
            created_at=row["created_at"],
        )

    def delete_contact(self, contact_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM contact WHERE contact_id = ?",
                (contact_id,),
            )
        return cursor.rowcount == 1

    @staticmethod
    def _user_key_from_row(row: sqlite3.Row) -> UserKey:
        return UserKey(
            key_id=str(row["key_id"]),
            display_name=str(row["display_name"]),
            fingerprint=str(row["fingerprint"]),
            encryption_public_key=bytes(row["encryption_public_key"]),
            signing_public_key=bytes(row["signing_public_key"]),
            kdf_salt=bytes(row["kdf_salt"]),
            kdf_opslimit=int(row["kdf_opslimit"]),
            kdf_memlimit=int(row["kdf_memlimit"]),
            encrypted_private_bundle=bytes(row["encrypted_private_bundle"]),
            created_at=str(row["created_at"]),
        )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

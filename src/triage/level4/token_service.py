"""Servicio criptográfico para generación y validación de tokens de autorización (Fase 4 - N4).

Genera tokens firmados criptográficamente mediante HMAC-SHA256 y secretos aleatorios,
vinculados a la propuesta, la aprobación y el resumen del contenido.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import logging
import secrets
import threading
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class TokenMetadata(BaseModel):
    """Metadatos de un token de autorización emitido."""
    token: str
    approval_id: str
    proposal_id: str
    proposal_hash: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    is_revoked: bool = False
    is_consumed: bool = False


class TokenService:
    """Gestor criptográfico de tokens de autorización de contención."""

    def __init__(
        self,
        secret_key: Optional[bytes] = None,
        default_ttl_seconds: int = 3600,
        single_use: bool = True,
    ) -> None:
        """Inicializar el servicio de tokens con clave secreta y tiempo de expiración."""
        if default_ttl_seconds <= 0:
            raise ValueError("default_ttl_seconds debe ser mayor que 0")

        self.secret_key = secret_key or secrets.token_bytes(32)
        self.default_ttl_seconds = default_ttl_seconds
        self.single_use = single_use
        self._tokens: dict[str, TokenMetadata] = {}
        self._lock = threading.RLock()

    def generate_token(
        self,
        approval_id: str,
        proposal_id: str,
        proposal_hash: str,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """Generar un token criptográficamente seguro con prefijo APR-."""
        if not approval_id or not proposal_id or not proposal_hash:
            raise ValueError("approval_id, proposal_id y proposal_hash son obligatorios")

        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(now.timestamp() + ttl, tz=timezone.utc)

        # Nonce criptográfico aleatorio
        nonce = secrets.token_hex(10)

        # Generar firma HMAC-SHA256
        data_to_sign = f"{approval_id}:{proposal_id}:{proposal_hash}:{nonce}:{int(expires_at.timestamp())}".encode("utf-8")
        signature = hmac.new(self.secret_key, data_to_sign, hashlib.sha256).hexdigest()[:20]

        # Formato de token compatible con mock_soc_api.py (APR-<hex>)
        token = f"APR-{nonce}{signature}"

        with self._lock:
            self._tokens[token] = TokenMetadata(
                token=token,
                approval_id=approval_id,
                proposal_id=proposal_id,
                proposal_hash=proposal_hash,
                issued_at=now,
                expires_at=expires_at,
            )

        logger.info(
            "Token de autorización emitido para propuesta %s (aprobación: %s)",
            proposal_id,
            approval_id,
        )
        return token

    def validate_token(
        self,
        token: str,
        approval_id: str,
        proposal_id: str,
        proposal_hash: str,
    ) -> bool:
        """Validar la autenticidad, vigencia y correspondencia del token."""
        if not token or not isinstance(token, str) or not token.startswith("APR-"):
            return False

        with self._lock:
            metadata = self._tokens.get(token)
            if not metadata:
                return False

            if metadata.is_revoked:
                logger.warning("Intento de uso de token revocado para propuesta %s", proposal_id)
                return False

            if self.single_use and metadata.is_consumed:
                logger.warning("Intento de reuso de token de un solo uso para propuesta %s", proposal_id)
                return False

            # Comprobar expiración
            now = datetime.now(timezone.utc)
            if now > metadata.expires_at:
                logger.warning("Token caducado para propuesta %s", proposal_id)
                return False

            # Comprobar correspondencia exacta
            if metadata.approval_id != str(approval_id):
                return False
            if metadata.proposal_id != str(proposal_id):
                return False
            if metadata.proposal_hash != str(proposal_hash):
                return False

            return True

    def consume_token(self, token: str) -> bool:
        """Marcar un token como consumido tras su uso en contención."""
        if not token:
            return False
        with self._lock:
            metadata = self._tokens.get(token)
            if not metadata or metadata.is_consumed or metadata.is_revoked:
                return False
            metadata.is_consumed = True
            return True

    def revoke_token(self, token: str) -> bool:
        """Revocar explícitamente un token."""
        if not token:
            return False
        with self._lock:
            metadata = self._tokens.get(token)
            if not metadata:
                return False
            metadata.is_revoked = True
            return True

    def is_consumed(self, token: str) -> bool:
        """Comprobar si el token ya fue utilizado."""
        with self._lock:
            metadata = self._tokens.get(token)
            return bool(metadata and metadata.is_consumed)

    def is_revoked(self, token: str) -> bool:
        """Comprobar si el token ha sido revocado."""
        with self._lock:
            metadata = self._tokens.get(token)
            return bool(metadata and metadata.is_revoked)

    def is_expired(self, token: str) -> bool:
        """Comprobar si el token ha caducado."""
        with self._lock:
            metadata = self._tokens.get(token)
            if not metadata:
                return True
            return datetime.now(timezone.utc) > metadata.expires_at

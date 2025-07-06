"""
zkAEDI Authenticated Encryption Module - Enhanced Version
=========================================================
Provides authenticated encryption with zero-knowledge properties
and comprehensive error handling for production environments.
"""

import os
import hmac
import hashlib
import json
import logging
import traceback
from typing import Dict, Tuple, Optional, Any, Union, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from enum import Enum
import base64
from threading import Lock

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag, InvalidSignature


# ===========================
# Custom Exception Hierarchy
# ===========================

class CryptoError(Exception):
    """Base exception for all cryptographic operations"""
    def __init__(self, message: str, error_code: str = None, 
                 context: Dict[str, Any] = None, recoverable: bool = False):
        super().__init__(message)
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.timestamp = datetime.utcnow()
        self.recoverable = recoverable


class EncryptionError(CryptoError):
    """Errors during encryption operations"""
    pass


class DecryptionError(CryptoError):
    """Errors during decryption operations"""
    pass


class AuthenticationError(CryptoError):
    """Errors related to authentication and integrity"""
    pass


class KeyDerivationError(CryptoError):
    """Errors during key derivation"""
    pass


class SerializationError(CryptoError):
    """Errors during data serialization/deserialization"""
    pass


class CommitmentError(CryptoError):
    """Errors related to commitments and proofs"""
    pass


class ConfigurationError(CryptoError):
    """Errors in configuration or initialization"""
    pass


# ===========================
# Error Severity Levels
# ===========================

class ErrorSeverity(Enum):
    """Severity levels for crypto errors"""
    CRITICAL = "critical"  # Key compromise, authentication failure
    HIGH = "high"         # Decryption failure, proof verification failure
    MEDIUM = "medium"     # Serialization issues, recoverable errors
    LOW = "low"          # Configuration warnings, non-critical issues


# ===========================
# Crypto Error Handler
# ===========================

@dataclass
class CryptoErrorConfig:
    """Configuration for cryptographic error handling"""
    log_errors: bool = True
    log_level: str = "ERROR"
    include_stacktrace: bool = True
    max_error_history: int = 1000
    notification_callbacks: List[Callable] = field(default_factory=list)
    recovery_strategies: Dict[str, Callable] = field(default_factory=dict)
    sanitize_keys: bool = True
    sanitize_data: bool = True
    error_metrics_enabled: bool = True
    auto_rotate_keys_on_error: bool = False
    max_retry_attempts: int = 3
    enable_forensics_mode: bool = False


class CryptoErrorHandler:
    """Specialized error handler for cryptographic operations"""
    
    def __init__(self, config: Optional[CryptoErrorConfig] = None):
        self.config = config or CryptoErrorConfig()
        self.error_history: List[Dict[str, Any]] = []
        self.error_metrics: Dict[str, int] = {}
        self.severity_counts: Dict[str, int] = {s.value: 0 for s in ErrorSeverity}
        self.operation_success_rate: Dict[str, Dict[str, int]] = {}
        self._lock = Lock()
        self._setup_logging()
        self._forensics_data: List[Dict[str, Any]] = []
    
    def _setup_logging(self):
        """Configure logging with crypto-specific formatting"""
        self.logger = logging.getLogger('zkAEDI.Crypto')
        self.logger.setLevel(getattr(logging, self.config.log_level))
        
        # Console handler
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - [%(levelname)s] - %(funcName)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler for critical errors
        file_handler = logging.FileHandler('crypto_errors.log')
        file_handler.setLevel(logging.ERROR)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def handle_error(self, error: Exception, operation: str = None,
                     context: Dict[str, Any] = None, 
                     severity: ErrorSeverity = None) -> Dict[str, Any]:
        """Handle cryptographic errors with appropriate severity"""
        with self._lock:
            # Determine severity if not provided
            if severity is None:
                severity = self._determine_severity(error)
            
            # Extract error details
            error_details = self._extract_error_details(error, operation, context, severity)
            
            # Log error
            if self.config.log_errors:
                self._log_crypto_error(error_details, severity)
            
            # Track error
            self._track_error(error_details)
            
            # Update metrics
            if self.config.error_metrics_enabled:
                self._update_metrics(error_details, operation)
            
            # Forensics mode
            if self.config.enable_forensics_mode:
                self._capture_forensics(error_details)
            
            # Notify stakeholders for critical errors
            if severity in [ErrorSeverity.CRITICAL, ErrorSeverity.HIGH]:
                self._notify_stakeholders(error_details)
            
            # Attempt recovery
            recovery_result = self._attempt_recovery(error, error_details)
            if recovery_result:
                error_details['recovery'] = recovery_result
            
            return error_details
    
    def _determine_severity(self, error: Exception) -> ErrorSeverity:
        """Determine error severity based on type"""
        severity_map = {
            AuthenticationError: ErrorSeverity.CRITICAL,
            KeyDerivationError: ErrorSeverity.CRITICAL,
            DecryptionError: ErrorSeverity.HIGH,
            EncryptionError: ErrorSeverity.HIGH,
            CommitmentError: ErrorSeverity.HIGH,
            SerializationError: ErrorSeverity.MEDIUM,
            ConfigurationError: ErrorSeverity.LOW
        }
        
        for error_type, severity in severity_map.items():
            if isinstance(error, error_type):
                return severity
        
        return ErrorSeverity.MEDIUM
    
    def _extract_error_details(self, error: Exception, operation: str,
                              context: Dict[str, Any], 
                              severity: ErrorSeverity) -> Dict[str, Any]:
        """Extract comprehensive error information"""
        details = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'operation': operation or 'unknown',
            'timestamp': datetime.utcnow().isoformat(),
            'severity': severity.value,
            'context': self._sanitize_context(context) if self.config.sanitize_data else context,
            'process_id': os.getpid()
        }
        
        if isinstance(error, CryptoError):
            details['error_code'] = error.error_code
            details['error_context'] = error.context
            details['recoverable'] = error.recoverable
        
        if self.config.include_stacktrace:
            details['stacktrace'] = traceback.format_exc()
        
        # Add crypto-specific details
        if isinstance(error, (InvalidTag, InvalidSignature)):
            details['crypto_failure'] = 'authentication'
            details['security_implication'] = 'potential tampering detected'
        
        return details
    
    def _sanitize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize sensitive cryptographic material"""
        if not context:
            return {}
        
        sensitive_patterns = [
            'key', 'secret', 'password', 'nonce', 'iv', 'tag',
            'plaintext', 'ciphertext', 'master', 'derive'
        ]
        
        sanitized = {}
        for key, value in context.items():
            key_lower = key.lower()
            if any(pattern in key_lower for pattern in sensitive_patterns):
                if isinstance(value, (str, bytes)):
                    # Keep first/last few chars for debugging
                    if len(str(value)) > 8:
                        sanitized[key] = f"{str(value)[:4]}...[REDACTED]...{str(value)[-4:]}"
                    else:
                        sanitized[key] = "[REDACTED]"
                else:
                    sanitized[key] = f"[REDACTED-{type(value).__name__}]"
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _log_crypto_error(self, error_details: Dict[str, Any], 
                         severity: ErrorSeverity):
        """Log error with crypto-specific formatting"""
        log_message = (
            f"[{severity.value.upper()}] Crypto operation '{error_details['operation']}' failed: "
            f"{error_details['error_type']} - {error_details['error_message']}"
        )
        
        if severity == ErrorSeverity.CRITICAL:
            self.logger.critical(log_message)
            # Additional alert for critical errors
            self.logger.critical(f"SECURITY ALERT: {error_details.get('security_implication', 'Critical crypto failure')}")
        elif severity == ErrorSeverity.HIGH:
            self.logger.error(log_message)
        elif severity == ErrorSeverity.MEDIUM:
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def _track_error(self, error_details: Dict[str, Any]):
        """Track error with enhanced categorization"""
        self.error_history.append(error_details)
        
        # Maintain history size
        if len(self.error_history) > self.config.max_error_history:
            self.error_history = self.error_history[-self.config.max_error_history:]
        
        # Update severity counts
        severity = error_details['severity']
        self.severity_counts[severity] += 1
    
    def _update_metrics(self, error_details: Dict[str, Any], operation: str):
        """Update operational metrics"""
        error_type = error_details['error_type']
        
        # Error type metrics
        self.error_metrics[error_type] = self.error_metrics.get(error_type, 0) + 1
        
        # Operation success rate tracking
        if operation:
            if operation not in self.operation_success_rate:
                self.operation_success_rate[operation] = {'success': 0, 'failure': 0}
            self.operation_success_rate[operation]['failure'] += 1
    
    def record_success(self, operation: str):
        """Record successful operation for metrics"""
        with self._lock:
            if operation not in self.operation_success_rate:
                self.operation_success_rate[operation] = {'success': 0, 'failure': 0}
            self.operation_success_rate[operation]['success'] += 1
    
    def _capture_forensics(self, error_details: Dict[str, Any]):
        """Capture detailed forensics data for security analysis"""
        forensics_entry = {
            **error_details,
            'system_state': {
                'memory_usage': self._get_memory_usage(),
                'active_operations': len(self.operation_success_rate),
                'error_rate': self._calculate_error_rate()
            }
        }
        self._forensics_data.append(forensics_entry)
        
        # Limit forensics data size
        if len(self._forensics_data) > 100:
            self._forensics_data = self._forensics_data[-100:]
    
    def _get_memory_usage(self) -> Dict[str, Any]:
        """Get current memory usage stats"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            return {
                'rss': process.memory_info().rss,
                'percent': process.memory_percent()
            }
        except ImportError:
            return {'available': False}
    
    def _calculate_error_rate(self) -> float:
        """Calculate overall error rate"""
        total_ops = sum(
            stats['success'] + stats['failure'] 
            for stats in self.operation_success_rate.values()
        )
        if total_ops == 0:
            return 0.0
        
        total_failures = sum(
            stats['failure'] 
            for stats in self.operation_success_rate.values()
        )
        return (total_failures / total_ops) * 100
    
    def _notify_stakeholders(self, error_details: Dict[str, Any]):
        """Notify registered callbacks about critical errors"""
        for callback in self.config.notification_callbacks:
            try:
                callback(error_details)
            except Exception as e:
                self.logger.warning(f"Notification callback failed: {e}")
    
    def _attempt_recovery(self, error: Exception, 
                         error_details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Attempt error recovery with crypto-specific strategies"""
        error_type = type(error).__name__
        
        # Built-in recovery strategies
        if isinstance(error, KeyDerivationError) and self.config.auto_rotate_keys_on_error:
            return {'action': 'key_rotation_recommended', 'status': 'pending'}
        
        # Custom recovery strategies
        if error_type in self.config.recovery_strategies:
            try:
                recovery_strategy = self.config.recovery_strategies[error_type]
                return recovery_strategy(error, error_details)
            except Exception as e:
                self.logger.warning(f"Recovery strategy failed: {e}")
        
        return None
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get comprehensive security and error summary"""
        return {
            'total_errors': len(self.error_history),
            'severity_breakdown': self.severity_counts,
            'critical_errors': self.severity_counts[ErrorSeverity.CRITICAL.value],
            'error_rate': self._calculate_error_rate(),
            'operation_metrics': self.operation_success_rate,
            'most_common_error': max(self.error_metrics.items(), key=lambda x: x[1])[0] if self.error_metrics else None,
            'recent_critical_errors': [
                e for e in self.error_history[-20:] 
                if e['severity'] == ErrorSeverity.CRITICAL.value
            ],
            'security_status': self._assess_security_status()
        }
    
    def _assess_security_status(self) -> str:
        """Assess overall security status based on errors"""
        critical_count = self.severity_counts[ErrorSeverity.CRITICAL.value]
        error_rate = self._calculate_error_rate()
        
        if critical_count > 5 or error_rate > 10:
            return 'compromised'
        elif critical_count > 0 or error_rate > 5:
            return 'degraded'
        else:
            return 'healthy'


# ===========================
# Validation Decorators
# ===========================

def validate_crypto_inputs(error_handler: CryptoErrorHandler = None):
    """Decorator for validating cryptographic inputs"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Extract self if this is a method
                if args and hasattr(args[0], 'error_handler'):
                    handler = args[0].error_handler
                else:
                    handler = error_handler
                
                # Perform validation based on function name
                if 'encrypt' in func.__name__:
                    _validate_encryption_inputs(*args, **kwargs)
                elif 'decrypt' in func.__name__:
                    _validate_decryption_inputs(*args, **kwargs)
                
                result = func(*args, **kwargs)
                
                # Record success
                if handler:
                    handler.record_success(func.__name__)
                
                return result
                
            except Exception as e:
                if handler:
                    error_details = handler.handle_error(
                        e,
                        operation=func.__name__,
                        context={'args_count': len(args), 'has_kwargs': bool(kwargs)}
                    )
                    
                    if not isinstance(e, CryptoError):
                        raise EncryptionError(
                            f"Validation failed in {func.__name__}: {str(e)}",
                            context=error_details
                        )
                raise
        
        return wrapper
    return decorator


def _validate_encryption_inputs(*args, **kwargs):
    """Validate inputs for encryption operations"""
    if len(args) > 1:
        plaintext = args[1] if len(args) > 1 else kwargs.get('plaintext')
        if plaintext is None:
            raise EncryptionError("Plaintext cannot be None")
        if isinstance(plaintext, str) and len(plaintext) == 0:
            raise EncryptionError("Plaintext cannot be empty")


def _validate_decryption_inputs(*args, **kwargs):
    """Validate inputs for decryption operations"""
    if len(args) > 1:
        encrypted_data = args[1] if len(args) > 1 else kwargs.get('encrypted_data')
        if encrypted_data is None:
            raise DecryptionError("Encrypted data cannot be None")


def ensure_initialized(error_handler: CryptoErrorHandler = None):
    """Decorator to ensure crypto system is properly initialized"""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                if not hasattr(self, 'master_key') or self.master_key is None:
                    raise ConfigurationError(
                        "Crypto system not properly initialized: missing master key"
                    )
                
                return func(self, *args, **kwargs)
                
            except Exception as e:
                handler = error_handler or getattr(self, 'error_handler', None)
                if handler:
                    handler.handle_error(e, operation=func.__name__)
                raise
        
        return wrapper
    return decorator


# ===========================
# Enhanced Data Structures
# ===========================

@dataclass
class EncryptedData:
    """Enhanced encrypted data container with validation"""
    ciphertext: str
    nonce: str
    tag: str
    algorithm: str = "AES-256-GCM"
    timestamp: datetime = None
    metadata: Dict[str, Any] = None
    version: int = 1
    key_id: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}
        
        # Validate required fields
        if not all([self.ciphertext, self.nonce, self.tag]):
            raise ConfigurationError(
                "Invalid EncryptedData: missing required fields",
                context={'has_ciphertext': bool(self.ciphertext),
                        'has_nonce': bool(self.nonce),
                        'has_tag': bool(self.tag)}
            )
        
        # Validate base64 encoding
        try:
            base64.b64decode(self.ciphertext)
            base64.b64decode(self.nonce)
            base64.b64decode(self.tag)
        except Exception:
            raise ConfigurationError("Invalid EncryptedData: fields must be base64 encoded")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'ciphertext': self.ciphertext,
            'nonce': self.nonce,
            'tag': self.tag,
            'algorithm': self.algorithm,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata,
            'version': self.version,
            'key_id': self.key_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptedData':
        """Create from dictionary"""
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


# ===========================
# Enhanced Authenticated Encryption
# ===========================

class AuthenticatedEncryption:
    """Enhanced authenticated encryption with comprehensive error handling"""

    def __init__(self, master_key: Optional[bytes] = None, 
                 error_handler: Optional[CryptoErrorHandler] = None):
        self.error_handler = error_handler or CryptoErrorHandler()
        self._initialize_crypto_system(master_key)
        self._key_rotation_count = 0
        self._operation_count = 0
    
    def _initialize_crypto_system(self, master_key: Optional[bytes] = None):
        """Initialize crypto system with validation"""
        try:
            if master_key is None:
                master_key = os.urandom(32)
                self.error_handler.logger.info("Generated new master key")
            elif len(master_key) != 32:
                raise ConfigurationError(
                    f"Invalid master key length: expected 32 bytes, got {len(master_key)}",
                    context={'key_length': len(master_key)}
                )
            
            self.master_key = master_key
            self.backend = default_backend()
            self._key_id = base64.b64encode(
                hashlib.sha256(master_key).digest()[:8]
            ).decode('utf-8')
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="crypto_initialization",
                severity=ErrorSeverity.CRITICAL
            )
            raise

    @ensure_initialized()
    def derive_key(self, context: str, salt: Optional[bytes] = None) -> bytes:
        """Enhanced key derivation with error handling"""
        try:
            # Validate context
            if not context or not isinstance(context, str):
                raise KeyDerivationError(
                    "Invalid key derivation context",
                    context={'context_type': type(context).__name__}
                )
            
            if salt is None:
                salt = os.urandom(16)
            elif len(salt) < 16:
                raise KeyDerivationError(
                    f"Salt too short: minimum 16 bytes, got {len(salt)}",
                    context={'salt_length': len(salt)}
                )

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )

            derived_key = kdf.derive(self.master_key + context.encode())
            
            # Verify key was derived successfully
            if len(derived_key) != 32:
                raise KeyDerivationError(
                    "Key derivation produced invalid output",
                    context={'output_length': len(derived_key)}
                )
            
            return derived_key
            
        except CryptoError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="key_derivation",
                context={'context': context, 'has_salt': salt is not None},
                severity=ErrorSeverity.CRITICAL
            )
            raise KeyDerivationError(f"Key derivation failed: {str(e)}")

    @validate_crypto_inputs()
    @ensure_initialized()
    def encrypt(self, plaintext: Union[str, bytes],
                associated_data: Optional[bytes] = None,
                context: Optional[str] = None) -> EncryptedData:
        """Enhanced encryption with comprehensive error handling"""
        try:
            # Convert plaintext to bytes
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Validate plaintext size
            if len(plaintext) > 64 * 1024 * 1024:  # 64MB limit
                raise EncryptionError(
                    "Plaintext too large (maximum 64MB)",
                    context={'size': len(plaintext)},
                    recoverable=True
                )
            
            # Use derived key if context provided
            if context:
                encryption_key = self.derive_key(context)
            else:
                encryption_key = self.master_key
            
            # Generate nonce
            nonce = os.urandom(12)  # 96 bits for GCM
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(nonce),
                backend=self.backend
            )
            
            encryptor = cipher.encryptor()
            
            # Add associated data if provided
            if associated_data:
                if not isinstance(associated_data, bytes):
                    raise EncryptionError(
                        "Associated data must be bytes",
                        context={'type': type(associated_data).__name__}
                    )
                encryptor.authenticate_additional_data(associated_data)
            
            # Encrypt
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Create encrypted data object
            encrypted_data = EncryptedData(
                ciphertext=base64.b64encode(ciphertext).decode('utf-8'),
                nonce=base64.b64encode(nonce).decode('utf-8'),
                tag=base64.b64encode(encryptor.tag).decode('utf-8'),
                algorithm="AES-256-GCM",
                key_id=self._key_id if not context else None,
                metadata={
                    'has_aad': associated_data is not None,
                    'context': context,
                    'operation_count': self._operation_count
                }
            )
            
            self._operation_count += 1
            return encrypted_data
            
        except CryptoError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="encryption",
                context={
                    'plaintext_size': len(plaintext) if plaintext else 0,
                    'has_aad': associated_data is not None,
                    'context': context
                },
                severity=ErrorSeverity.HIGH
            )
            raise EncryptionError(f"Encryption failed: {str(e)}")

    @validate_crypto_inputs()
    @ensure_initialized()
    def decrypt(self, encrypted_data: EncryptedData,
                associated_data: Optional[bytes] = None,
                context: Optional[str] = None) -> bytes:
        """Enhanced decryption with authentication verification"""
        try:
            # Validate encrypted data version
            if hasattr(encrypted_data, 'version') and encrypted_data.version != 1:
                raise DecryptionError(
                    f"Unsupported encrypted data version: {encrypted_data.version}",
                    context={'supported_versions': [1]}
                )
            
            # Decode from base64
            try:
                ciphertext = base64.b64decode(encrypted_data.ciphertext)
                nonce = base64.b64decode(encrypted_data.nonce)
                tag = base64.b64decode(encrypted_data.tag)
            except Exception as e:
                raise DecryptionError(
                    "Failed to decode encrypted data",
                    context={'error': str(e)},
                    recoverable=False
                )
            
            # Validate sizes
            if len(nonce) != 12:
                raise DecryptionError(
                    f"Invalid nonce size: expected 12 bytes, got {len(nonce)}",
                    recoverable=False
                )
            
            if len(tag) != 16:
                raise DecryptionError(
                    f"Invalid tag size: expected 16 bytes, got {len(tag)}",
                    recoverable=False
                )
            
            # Use appropriate key
            if context:
                decryption_key = self.derive_key(context)
            else:
                decryption_key = self.master_key
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(decryption_key),
                modes.GCM(nonce, tag),
                backend=self.backend
            )
            
            decryptor = cipher.decryptor()
            
            # Add associated data if provided
            if associated_data:
                decryptor.authenticate_additional_data(associated_data)
            
            # Decrypt and verify
            try:
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                self._operation_count += 1
                return plaintext
                
            except InvalidTag:
                self.error_handler.handle_error(
                    AuthenticationError(
                        "Authentication tag verification failed - data may be tampered",
                        error_code="AUTH_TAG_INVALID",
                        recoverable=False
                    ),
                    operation="decryption_auth",
                    context={'key_id': encrypted_data.key_id},
                    severity=ErrorSeverity.CRITICAL
                )
                raise
            
        except CryptoError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="decryption",
                context={
                    'has_aad': associated_data is not None,
                    'algorithm': encrypted_data.algorithm,
                    'timestamp': encrypted_data.timestamp.isoformat() if encrypted_data.timestamp else None
                },
                severity=ErrorSeverity.HIGH
            )
            raise DecryptionError(f"Decryption failed: {str(e)}")

    @validate_crypto_inputs()
    def encrypt_json(self, data: Dict[str, Any], 
                    context: Optional[str] = None) -> EncryptedData:
        """Encrypt JSON data with validation"""
        try:
            # Validate data
            if not isinstance(data, dict):
                raise SerializationError(
                    f"Expected dict, got {type(data).__name__}",
                    context={'data_type': type(data).__name__}
                )
            
            # Serialize with error handling
            try:
                json_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
            except (TypeError, ValueError) as e:
                raise SerializationError(
                    f"Failed to serialize JSON: {str(e)}",
                    context={'keys': list(data.keys()) if data else []},
                    recoverable=True
                )
            
            return self.encrypt(json_bytes, context=context)
            
        except CryptoError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="encrypt_json",
                context={'data_keys': list(data.keys()) if isinstance(data, dict) else None}
            )
            raise

    @validate_crypto_inputs()
    def decrypt_json(self, encrypted_data: EncryptedData,
                    context: Optional[str] = None) -> Dict[str, Any]:
        """Decrypt JSON data with validation"""
        try:
            plaintext = self.decrypt(encrypted_data, context=context)
            
            # Deserialize with error handling
            try:
                return json.loads(plaintext.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise SerializationError(
                    f"Failed to deserialize JSON: {str(e)}",
                    context={'data_size': len(plaintext)},
                    recoverable=False
                )
            
        except CryptoError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="decrypt_json",
                context={'encrypted_at': encrypted_data.timestamp.isoformat() if encrypted_data.timestamp else None}
            )
            raise

    def rotate_master_key(self, new_master_key: Optional[bytes] = None) -> str:
        """Rotate master key with proper error handling"""
        try:
            old_key_id = self._key_id
            
            # Generate new key if not provided
            if new_master_key is None:
                new_master_key = os.urandom(32)
            
            # Re-initialize with new key
            self._initialize_crypto_system(new_master_key)
            self._key_rotation_count += 1
            
            self.error_handler.logger.info(
                f"Master key rotated successfully. Old key ID: {old_key_id}, New key ID: {self._key_id}"
            )
            
            return self._key_id
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="key_rotation",
                severity=ErrorSeverity.CRITICAL
            )
            raise


# ===========================
# Enhanced ZK Authenticated Encryption
# ===========================

class ZKAuthenticatedEncryption(AuthenticatedEncryption):
    """Zero-knowledge authenticated encryption with enhanced error handling"""

    def __init__(self, master_key: Optional[bytes] = None,
                 error_handler: Optional[CryptoErrorHandler] = None):
        super().__init__(master_key, error_handler)
        self.commitments: Dict[str, str] = {}
        self.proof_verifications: Dict[str, bool] = {}
        self._commitment_lock = Lock()
    
    @validate_crypto_inputs()
    def encrypt_with_proof(self, plaintext: Union[str, bytes],
                          proof_data: Dict[str, Any],
                          context: Optional[str] = None) -> Tuple[EncryptedData, str]:
        """Enhanced encryption with zero-knowledge proof binding"""
        try:
            # Validate proof data
            if not isinstance(proof_data, dict):
                raise CommitmentError(
                    "Proof data must be a dictionary",
                    context={'type': type(proof_data).__name__}
                )
            
            # Create commitment to plaintext
            if isinstance(plaintext, str):
                plaintext_bytes = plaintext.encode('utf-8')
            else:
                plaintext_bytes = plaintext
            
            commitment = self._commit_to_data(plaintext_bytes)
            
            # Use commitment as associated data
            associated_data = commitment.encode('utf-8')
            
            # Encrypt with commitment binding
            encrypted = self.encrypt(plaintext_bytes, associated_data, context)
            
            # Generate proof ID
            proof_id = base64.b64encode(os.urandom(16)).decode('utf-8')
            
            # Store commitment securely
            with self._commitment_lock:
                self.commitments[proof_id] = commitment
            
            # Add proof data to metadata
            encrypted.metadata.update({
                'proof_id': proof_id,
                'proof_data': proof_data,
                'proof_timestamp': datetime.utcnow().isoformat(),
                'commitment_scheme': 'SHA256'
            })
            
            self.error_handler.logger.info(
                f"Created ZK proof for encryption: proof_id={proof_id[:8]}..."
            )
            
            return encrypted, commitment
            
        except CryptoError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="encrypt_with_proof",
                context={'has_proof_data': bool(proof_data)},
                severity=ErrorSeverity.HIGH
            )
            raise CommitmentError(f"Failed to encrypt with proof: {str(e)}")
    
    @validate_crypto_inputs()
    def decrypt_with_verification(self, encrypted_data: EncryptedData,
                                 expected_commitment: str,
                                 context: Optional[str] = None) -> Tuple[bytes, bool]:
        """Enhanced decryption with commitment verification"""
        try:
            # Validate expected commitment format
            if not expected_commitment or not isinstance(expected_commitment, str):
                raise CommitmentError(
                    "Invalid commitment format",
                    context={'type': type(expected_commitment).__name__}
                )
            
            # Get proof ID from metadata
            proof_id = encrypted_data.metadata.get('proof_id')
            if not proof_id:
                self.error_handler.handle_error(
                    CommitmentError("No proof ID in encrypted data"),
                    operation="decrypt_verification",
                    severity=ErrorSeverity.HIGH
                )
                return b"", False
            
            # Retrieve stored commitment
            with self._commitment_lock:
                stored_commitment = self.commitments.get(proof_id)
            
            if not stored_commitment:
                self.error_handler.handle_error(
                    CommitmentError(f"No commitment found for proof ID: {proof_id[:8]}..."),
                    operation="decrypt_verification",
                    severity=ErrorSeverity.HIGH
                )
                return b"", False
            
            # Verify commitment matches
            if not hmac.compare_digest(stored_commitment, expected_commitment):
                self.error_handler.handle_error(
                    AuthenticationError(
                        "Commitment verification failed",
                        error_code="COMMITMENT_MISMATCH",
                        context={'proof_id': proof_id[:8] + '...'},
                        recoverable=False
                    ),
                    operation="commitment_verification",
                    severity=ErrorSeverity.CRITICAL
                )
                self.proof_verifications[proof_id] = False
                return b"", False
            
            # Decrypt with commitment as associated data
            associated_data = expected_commitment.encode('utf-8')
            
            try:
                plaintext = self.decrypt(encrypted_data, associated_data, context)
                
                # Verify decrypted data matches commitment
                computed_commitment = self._commit_to_data(plaintext)
                
                if not hmac.compare_digest(computed_commitment, expected_commitment):
                    self.error_handler.handle_error(
                        AuthenticationError(
                            "Decrypted data doesn't match commitment",
                            error_code="DATA_COMMITMENT_MISMATCH",
                            recoverable=False
                        ),
                        operation="post_decrypt_verification",
                        severity=ErrorSeverity.CRITICAL
                    )
                    self.proof_verifications[proof_id] = False
                    return b"", False
                
                # Success
                self.proof_verifications[proof_id] = True
                self.error_handler.logger.info(
                    f"ZK proof verification successful: proof_id={proof_id[:8]}..."
                )
                
                return plaintext, True
                
            except (DecryptionError, InvalidTag) as e:
                self.proof_verifications[proof_id] = False
                return b"", False
            
        except CryptoError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="decrypt_with_verification",
                context={'has_proof_id': bool(encrypted_data.metadata.get('proof_id'))},
                severity=ErrorSeverity.HIGH
            )
            return b"", False
    
    def _commit_to_data(self, data: bytes) -> str:
        """Create cryptographic commitment with validation"""
        try:
            if not isinstance(data, bytes):
                raise CommitmentError(
                    f"Data must be bytes, got {type(data).__name__}",
                    recoverable=True
                )
            
            if len(data) == 0:
                raise CommitmentError("Cannot commit to empty data")
            
            # Use HMAC for commitment to prevent length extension attacks
            commitment = hmac.new(
                self.master_key,
                data,
                hashlib.sha256
            ).hexdigest()
            
            return commitment
            
        except CryptoError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="data_commitment",
                context={'data_size': len(data) if data else 0}
            )
            raise CommitmentError(f"Commitment generation failed: {str(e)}")
    
    @validate_crypto_inputs()
    def create_data_proof(self, data: bytes, statement: str,
                         additional_claims: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Enhanced proof creation with comprehensive validation"""
        try:
            # Validate inputs
            if not isinstance(data, bytes):
                raise CommitmentError(
                    f"Data must be bytes, got {type(data).__name__}"
                )
            
            if not statement or not isinstance(statement, str):
                raise CommitmentError("Statement must be a non-empty string")
            
            # Create commitment
            commitment = self._commit_to_data(data)
            
            # Build proof structure
            proof = {
                "commitment": commitment,
                "statement": statement,
                "timestamp": datetime.utcnow().isoformat(),
                "proof_type": "data_knowledge",
                "hash_algorithm": "HMAC-SHA256",
                "version": 1,
                "claims": additional_claims or {}
            }
            
            # Sign the proof
            proof_bytes = json.dumps(proof, sort_keys=True).encode('utf-8')
            signature = hmac.new(
                self.master_key,
                proof_bytes,
                hashlib.sha256
            ).hexdigest()
            
            proof["signature"] = signature
            
            # Store proof for later verification
            proof_id = base64.b64encode(os.urandom(8)).decode('utf-8')
            proof["proof_id"] = proof_id
            
            self.error_handler.logger.info(
                f"Created data proof: id={proof_id}, statement='{statement[:50]}...'"
            )
            
            return proof
            
        except CryptoError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="create_data_proof",
                context={'statement_length': len(statement) if statement else 0}
            )
            raise CommitmentError(f"Proof creation failed: {str(e)}")
    
    @validate_crypto_inputs()
    def verify_data_proof(self, proof: Dict[str, Any]) -> bool:
        """Enhanced proof verification with detailed error reporting"""
        try:
            # Validate proof structure
            required_fields = ['commitment', 'statement', 'timestamp', 
                             'proof_type', 'signature']
            missing_fields = [f for f in required_fields if f not in proof]
            
            if missing_fields:
                raise CommitmentError(
                    f"Missing required proof fields: {missing_fields}",
                    context={'provided_fields': list(proof.keys())}
                )
            
            # Validate proof version
            proof_version = proof.get('version', 0)
            if proof_version != 1:
                raise CommitmentError(
                    f"Unsupported proof version: {proof_version}",
                    context={'supported_versions': [1]}
                )
            
            # Extract and remove signature for verification
            proof_copy = proof.copy()
            signature = proof_copy.pop("signature")
            
            # Recompute signature
            proof_bytes = json.dumps(proof_copy, sort_keys=True).encode('utf-8')
            expected_signature = hmac.new(
                self.master_key,
                proof_bytes,
                hashlib.sha256
            ).hexdigest()
            
            # Verify signature
            is_valid = hmac.compare_digest(signature, expected_signature)
            
            if is_valid:
                self.error_handler.logger.info(
                    f"Proof verification successful: id={proof.get('proof_id', 'unknown')}"
                )
            else:
                self.error_handler.handle_error(
                    AuthenticationError(
                        "Proof signature verification failed",
                        error_code="PROOF_SIGNATURE_INVALID"
                    ),
                    operation="verify_data_proof",
                    severity=ErrorSeverity.HIGH
                )
            
            return is_valid
            
        except CryptoError:
            self.error_handler.handle_error(
                CommitmentError("Proof verification error"),
                operation="verify_data_proof",
                severity=ErrorSeverity.HIGH
            )
            return False
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="verify_data_proof",
                context={'proof_type': proof.get('proof_type', 'unknown')}
            )
            return False
    
    def get_proof_status(self) -> Dict[str, Any]:
        """Get comprehensive proof verification status"""
        with self._commitment_lock:
            total_commitments = len(self.commitments)
            verified_proofs = sum(1 for v in self.proof_verifications.values() if v)
            failed_proofs = sum(1 for v in self.proof_verifications.values() if not v)
        
        return {
            'total_commitments': total_commitments,
            'verified_proofs': verified_proofs,
            'failed_proofs': failed_proofs,
            'verification_rate': (verified_proofs / max(verified_proofs + failed_proofs, 1)) * 100,
            'active_commitments': list(self.commitments.keys())[:10]  # First 10 for privacy
        }


# ===========================
# Factory Functions
# ===========================

def create_authenticated_encryption(key: Optional[bytes] = None,
                                  error_config: Optional[CryptoErrorConfig] = None) -> AuthenticatedEncryption:
    """Factory function with comprehensive initialization"""
    try:
        error_handler = CryptoErrorHandler(error_config)
        return AuthenticatedEncryption(key, error_handler)
    except Exception as e:
        logging.critical(f"Failed to initialize authenticated encryption: {str(e)}")
        raise


def create_zk_authenticated_encryption(key: Optional[bytes] = None,
                                     error_config: Optional[CryptoErrorConfig] = None) -> ZKAuthenticatedEncryption:
    """Factory function for ZK authenticated encryption"""
    try:
        error_handler = CryptoErrorHandler(error_config)
        return ZKAuthenticatedEncryption(key, error_handler)
    except Exception as e:
        logging.critical(f"Failed to initialize ZK authenticated encryption: {str(e)}")
        raise


# ===========================
# Usage Examples
# ===========================

if __name__ == "__main__":
    # Configure error handling
    error_config = CryptoErrorConfig(
        log_errors=True,
        log_level="INFO",
        include_stacktrace=True,
        error_metrics_enabled=True,
        sanitize_keys=True,
        sanitize_data=True,
        auto_rotate_keys_on_error=False,
        enable_forensics_mode=True
    )
    
    # Add security alert callback
    def security_alert(error_details: Dict[str, Any]):
        if error_details['severity'] in ['critical', 'high']:
            print(f"\n🚨 SECURITY ALERT: {error_details['error_message']}")
            print(f"   Operation: {error_details['operation']}")
            print(f"   Severity: {error_details['severity'].upper()}")
            if 'security_implication' in error_details:
                print(f"   Implication: {error_details['security_implication']}")
    
    error_config.notification_callbacks.append(security_alert)
    
    try:
        # Initialize systems
        print("Initializing authenticated encryption systems...")
        ae = create_authenticated_encryption(error_config=error_config)
        zk_ae = create_zk_authenticated_encryption(error_config=error_config)
        
        # Test standard encryption
        print("\n1. Testing standard authenticated encryption...")
        test_data = "Sensitive information that needs protection"
        encrypted = ae.encrypt(test_data, context="user_data")
        print(f"   Encrypted successfully: {encrypted.ciphertext[:32]}...")
        
        decrypted = ae.decrypt(encrypted, context="user_data")
        print(f"   Decrypted successfully: {decrypted.decode()[:32]}...")
        
        # Test JSON encryption
        print("\n2. Testing JSON encryption...")
        json_data = {
            "user_id": "12345",
            "balance": 1000.50,
            "transactions": ["tx1", "tx2", "tx3"]
        }
        encrypted_json = ae.encrypt_json(json_data)
        print(f"   JSON encrypted: {encrypted_json.ciphertext[:32]}...")
        
        decrypted_json = ae.decrypt_json(encrypted_json)
        print(f"   JSON decrypted: {list(decrypted_json.keys())}")
        
        # Test ZK encryption with proof
        print("\n3. Testing ZK authenticated encryption...")
        secret_data = b"This data has zero-knowledge properties"
        proof_data = {"purpose": "audit", "requester": "compliance_dept"}
        
        zk_encrypted, commitment = zk_ae.encrypt_with_proof(
            secret_data,
            proof_data,
            context="zk_audit"
        )
        print(f"   ZK encrypted with commitment: {commitment[:32]}...")
        
        # Test ZK decryption with verification
        print("\n4. Testing ZK decryption with verification...")
        zk_decrypted, verified = zk_ae.decrypt_with_verification(
            zk_encrypted,
            commitment,
            context="zk_audit"
        )
        print(f"   Verification result: {'✓ PASSED' if verified else '✗ FAILED'}")
        if verified:
            print(f"   Decrypted data: {zk_decrypted.decode()[:32]}...")
        
        # Test data proof
        print("\n5. Testing data proof generation...")
        proof = zk_ae.create_data_proof(
            b"Confidential data",
            "Data was processed according to GDPR requirements",
            {"compliance": "GDPR", "retention": "30 days"}
        )
        print(f"   Proof created: id={proof['proof_id']}")
        
        # Verify proof
        is_valid_proof = zk_ae.verify_data_proof(proof)
        print(f"   Proof verification: {'✓ VALID' if is_valid_proof else '✗ INVALID'}")
        
        # Test error handling - invalid decryption
        print("\n6. Testing error handling...")
        try:
            # Corrupt the tag to trigger authentication failure
            corrupted = EncryptedData(
                ciphertext=encrypted.ciphertext,
                nonce=encrypted.nonce,
                tag=base64.b64encode(b"corrupted_tag_12").decode('utf-8'),
                algorithm=encrypted.algorithm
            )
            ae.decrypt(corrupted)
        except AuthenticationError as e:
            print(f"   ✓ Authentication error caught: {e.error_code}")
        
        # Get security summary
        print("\n7. Security and error summary:")
        summary = ae.error_handler.get_security_summary()
        print(f"   Total operations: {ae._operation_count}")
        print(f"   Error rate: {summary['error_rate']:.2f}%")
        print(f"   Security status: {summary['security_status'].upper()}")
        print(f"   Critical errors: {summary['critical_errors']}")
        
        # Get ZK proof status
        zk_status = zk_ae.get_proof_status()
        print(f"\n8. ZK Proof Status:")
        print(f"   Total commitments: {zk_status['total_commitments']}")
        print(f"   Verified proofs: {zk_status['verified_proofs']}")
        print(f"   Verification rate: {zk_status['verification_rate']:.1f}%")
        
        # Test key rotation
        print("\n9. Testing key rotation...")
        old_key_id = ae._key_id
        new_key_id = ae.rotate_master_key()
        print(f"   Key rotated: {old_key_id} → {new_key_id}")
        
    except CryptoError as e:
        print(f"\n❌ Crypto Error: {e}")
        print(f"   Error code: {e.error_code}")
        print(f"   Recoverable: {e.recoverable}")
        print(f"   Context: {e.context}")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        traceback.print_exc()

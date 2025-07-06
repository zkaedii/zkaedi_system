"""
zkAEDI Core Zero-Knowledge Primitives - Enhanced Version
========================================================
Advanced cryptographic primitives with comprehensive error handling,
validation, and monitoring capabilities.
"""

import hashlib
import secrets
import logging
import traceback
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
import json


# ===========================
# Custom Exception Hierarchy
# ===========================

class ZKError(Exception):
    """Base exception for all ZK-related errors"""

    def __init__(self, message: str, error_code: str = None, context: Dict[str, Any] = None):
        super().__init__(message)
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.timestamp = datetime.utcnow()


class ZKCryptographicError(ZKError):
    """Errors related to cryptographic operations"""
    pass


class ZKValidationError(ZKError):
    """Errors related to input validation"""
    pass


class ZKProofError(ZKError):
    """Errors related to proof generation/verification"""
    pass


class ZKParameterError(ZKError):
    """Errors related to invalid parameters"""
    pass


class ZKStateError(ZKError):
    """Errors related to invalid state transitions"""
    pass


# ===========================
# Error Handling Configuration
# ===========================

@dataclass
class ErrorHandlerConfig:
    """Configuration for error handling behavior"""
    log_errors: bool = True
    log_level: str = "ERROR"
    include_stacktrace: bool = True
    max_error_history: int = 1000
    notification_callbacks: List[Callable] = field(default_factory=list)
    recovery_strategies: Dict[str, Callable] = field(default_factory=dict)
    sanitize_sensitive_data: bool = True
    error_metrics_enabled: bool = True


# ===========================
# Comprehensive Error Handler
# ===========================

class ZKErrorHandler:
    """Centralized error handling system for ZK operations"""

    def __init__(self, config: Optional[ErrorHandlerConfig] = None):
        self.config = config or ErrorHandlerConfig()
        self.error_history: List[Dict[str, Any]] = []
        self.error_metrics: Dict[str, int] = {}
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging system"""
        self.logger = logging.getLogger('zkAEDI')
        self.logger.setLevel(getattr(logging, self.config.log_level))

        # Console handler with formatting
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def handle_error(self, error: Exception, operation: str = None,
                     context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Comprehensive error handling with tracking and recovery"""
        error_details = self._extract_error_details(error, operation, context)

        # Log error
        if self.config.log_errors:
            self._log_error(error_details)

        # Track error
        self._track_error(error_details)

        # Update metrics
        if self.config.error_metrics_enabled:
            self._update_metrics(error_details)

        # Notify stakeholders
        self._notify_stakeholders(error_details)

        # Attempt recovery
        recovery_result = self._attempt_recovery(error, error_details)
        if recovery_result:
            error_details['recovery'] = recovery_result

        return error_details

    def _extract_error_details(self, error: Exception, operation: str,
                               context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract comprehensive error information"""
        details = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'operation': operation,
            'timestamp': datetime.utcnow().isoformat(),
            'context': self._sanitize_context(context) if self.config.sanitize_sensitive_data else context
        }

        if isinstance(error, ZKError):
            details['error_code'] = error.error_code
            details['error_context'] = error.context

        if self.config.include_stacktrace:
            details['stacktrace'] = traceback.format_exc()

        return details

    def _sanitize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from context"""
        if not context:
            return {}

        sensitive_keys = ['secret', 'private_key', 'randomness', 'witness']
        sanitized = {}

        for key, value in context.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value

        return sanitized

    def _log_error(self, error_details: Dict[str, Any]):
        """Log error with appropriate level"""
        log_message = (
            f"Error in operation '{error_details.get('operation', 'unknown')}': "
            f"{error_details['error_type']} - {error_details['error_message']}"
        )

        if error_details['error_type'] in ['ZKCryptographicError', 'ZKProofError']:
            self.logger.critical(log_message)
        else:
            self.logger.error(log_message)

    def _track_error(self, error_details: Dict[str, Any]):
        """Track error in history with size limit"""
        self.error_history.append(error_details)

        # Maintain size limit
        if len(self.error_history) > self.config.max_error_history:
            self.error_history = self.error_history[-self.config.max_error_history:]

    def _update_metrics(self, error_details: Dict[str, Any]):
        """Update error metrics for monitoring"""
        error_type = error_details['error_type']
        operation = error_details.get('operation', 'unknown')

        # Update error type counter
        self.error_metrics[error_type] = self.error_metrics.get(
            error_type, 0) + 1

        # Update operation error counter
        op_key = f"operation_{operation}"
        self.error_metrics[op_key] = self.error_metrics.get(op_key, 0) + 1

    def _notify_stakeholders(self, error_details: Dict[str, Any]):
        """Notify registered callbacks about errors"""
        for callback in self.config.notification_callbacks:
            try:
                callback(error_details)
            except Exception as e:
                self.logger.warning(f"Notification callback failed: {e}")

    def _attempt_recovery(self, error: Exception, error_details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Attempt to recover from error using registered strategies"""
        error_type = type(error).__name__

        if error_type in self.config.recovery_strategies:
            try:
                recovery_strategy = self.config.recovery_strategies[error_type]
                return recovery_strategy(error, error_details)
            except Exception as e:
                self.logger.warning(f"Recovery strategy failed: {e}")

        return None

    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of error metrics and recent errors"""
        return {
            'total_errors': len(self.error_history),
            'error_metrics': self.error_metrics,
            'recent_errors': self.error_history[-10:],
            'most_common_error': max(self.error_metrics.items(), key=lambda x: x[1])[0] if self.error_metrics else None
        }


# ===========================
# Validation Decorators
# ===========================

def validate_inputs(validator_func: Callable = None, error_handler: ZKErrorHandler = None):
    """Decorator for input validation with error handling"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Run custom validator if provided
                if validator_func:
                    validator_func(*args, **kwargs)

                return func(*args, **kwargs)

            except Exception as e:
                if error_handler:
                    error_details = error_handler.handle_error(
                        e,
                        operation=func.__name__,
                        context={'args': args, 'kwargs': kwargs}
                    )

                    # Re-raise with enhanced error
                    if isinstance(e, ZKError):
                        raise
                    else:
                        raise ZKValidationError(
                            f"Validation failed in {func.__name__}: {str(e)}",
                            context=error_details
                        )
                else:
                    raise

        return wrapper
    return decorator


def ensure_state(required_state: str = None, error_handler: ZKErrorHandler = None):
    """Decorator to ensure object is in required state"""
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            try:
                if required_state and hasattr(self, 'state'):
                    if self.state != required_state:
                        raise ZKStateError(
                            f"Invalid state: expected '{required_state}', got '{self.state}'",
                            context={'method': func.__name__,
                                     'current_state': self.state}
                        )

                return func(self, *args, **kwargs)

            except Exception as e:
                if error_handler:
                    error_handler.handle_error(e, operation=func.__name__)
                raise

        return wrapper
    return decorator


# ===========================
# Enhanced ZK Types
# ===========================

class ProofType(Enum):
    """Types of zero-knowledge proofs supported"""
    SCHNORR = "schnorr"
    BULLETPROOF = "bulletproof"
    GROTH16 = "groth16"
    PLONK = "plonk"
    STARK = "stark"


@dataclass
class ZKProof:
    """Zero-knowledge proof structure with validation"""
    proof_type: ProofType
    commitment: str
    challenge: str
    response: str
    public_input: Optional[Dict[str, Any]] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate proof structure after initialization"""
        if not all([self.commitment, self.challenge, self.response]):
            raise ZKValidationError(
                "Invalid proof: missing required components",
                context={'proof_type': self.proof_type.value}
            )


@dataclass
class ZKCommitment:
    """Commitment structure with validation"""
    value: str
    randomness: str
    binding: bool = True
    hiding: bool = True
    scheme: str = "pedersen"

    def __post_init__(self):
        """Validate commitment after initialization"""
        if not self.value or not self.randomness:
            raise ZKValidationError(
                "Invalid commitment: missing value or randomness")


# ===========================
# Enhanced ZK Primitives
# ===========================

class ZKPrimitives:
    """Core zero-knowledge cryptographic primitives with comprehensive error handling"""

    def __init__(self, security_parameter: int = 256, error_handler: Optional[ZKErrorHandler] = None):
        self.error_handler = error_handler or ZKErrorHandler()
        self.state = "uninitialized"

        try:
            self._validate_security_parameter(security_parameter)
            self.security_parameter = security_parameter
            self.prime = self._generate_safe_prime()
            self.generator = 2  # Simple generator for demonstration
            self.state = "initialized"

        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="initialization",
                context={'security_parameter': security_parameter}
            )
            raise

    def _validate_security_parameter(self, param: int):
        """Validate security parameter"""
        if not isinstance(param, int):
            raise ZKParameterError("Security parameter must be an integer")

        if param < 128:
            raise ZKParameterError(
                "Security parameter too small (minimum 128 bits)",
                context={'provided': param, 'minimum': 128}
            )

        if param > 512:
            raise ZKParameterError(
                "Security parameter too large (maximum 512 bits)",
                context={'provided': param, 'maximum': 512}
            )

    def _generate_safe_prime(self) -> int:
        """Generate a safe prime with error handling"""
        try:
            # Simplified for demonstration - use proper prime generation in production
            prime_candidates = {
                128: 2**128 - 159,
                256: 2**256 - 189,
                512: 2**512 - 569
            }

            if self.security_parameter in prime_candidates:
                return prime_candidates[self.security_parameter]
            else:
                # Default to closest available
                return 2**256 - 189

        except Exception as e:
            raise ZKCryptographicError(
                f"Failed to generate safe prime: {str(e)}",
                context={'security_parameter': self.security_parameter}
            )

    @validate_inputs()
    def hash_to_scalar(self, *args) -> int:
        """Hash arbitrary inputs to a scalar value with validation"""
        if not args:
            raise ZKValidationError("No input provided for hashing")

        try:
            data = "".join(str(arg) for arg in args)
            hash_bytes = hashlib.sha256(data.encode()).digest()
            return int.from_bytes(hash_bytes, 'big') % self.prime

        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="hash_to_scalar",
                context={'input_count': len(args)}
            )
            raise ZKCryptographicError(f"Hashing failed: {str(e)}")

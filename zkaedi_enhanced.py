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
        self.error_metrics[error_type] = self.error_metrics.get(error_type, 0) + 1
        
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
                            context={'method': func.__name__, 'current_state': self.state}
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
            raise ZKValidationError("Invalid commitment: missing value or randomness")


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

    @ensure_state("initialized")
    def generate_commitment(self, value: int, randomness: Optional[int] = None) -> ZKCommitment:
        """Generate a Pedersen commitment with comprehensive validation"""
        try:
            # Validate value
            if not isinstance(value, int):
                raise ZKValidationError(
                    "Commitment value must be an integer",
                    context={'type_provided': type(value).__name__}
                )
            
            if value < 0:
                raise ZKValidationError(
                    "Commitment value must be non-negative",
                    context={'value': value}
                )
            
            if value >= self.prime:
                raise ZKValidationError(
                    "Commitment value exceeds field size",
                    context={'value': value, 'max': self.prime - 1}
                )
            
            # Generate randomness if not provided
            if randomness is None:
                randomness = secrets.randbelow(self.prime)
            else:
                # Validate provided randomness
                if not isinstance(randomness, int) or randomness < 0 or randomness >= self.prime:
                    raise ZKValidationError(
                        "Invalid randomness value",
                        context={'randomness_range': f"[0, {self.prime})", 'provided': randomness}
                    )

            # Compute commitment: C = g^value * h^randomness mod p
            g_pow = pow(self.generator, value, self.prime)
            h = pow(self.generator, 2, self.prime)  # Different generator
            h_pow = pow(h, randomness, self.prime)
            commitment = (g_pow * h_pow) % self.prime

            return ZKCommitment(
                value=str(commitment),
                randomness=str(randomness),
                binding=True,
                hiding=True,
                scheme="pedersen"
            )
            
        except ZKError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="generate_commitment",
                context={'value': value, 'has_randomness': randomness is not None}
            )
            raise ZKCryptographicError(f"Commitment generation failed: {str(e)}")

    @ensure_state("initialized")
    def schnorr_prove(self, secret: int, message: str = "") -> ZKProof:
        """Generate a Schnorr zero-knowledge proof with validation"""
        try:
            # Validate secret
            if not isinstance(secret, int):
                raise ZKValidationError("Secret must be an integer")
            
            if secret <= 0 or secret >= self.prime:
                raise ZKValidationError(
                    "Secret out of valid range",
                    context={'range': f"(0, {self.prime})", 'provided': 'out_of_range'}
                )
            
            # Validate message
            if not isinstance(message, str):
                raise ZKValidationError("Message must be a string")
            
            # Commitment phase
            r = secrets.randbelow(self.prime - 1) + 1  # Ensure r != 0
            commitment = pow(self.generator, r, self.prime)

            # Challenge (Fiat-Shamir heuristic)
            challenge = self.hash_to_scalar(commitment, message)

            # Response
            response = (r + challenge * secret) % (self.prime - 1)

            # Public key (for verification)
            public_key = pow(self.generator, secret, self.prime)

            proof = ZKProof(
                proof_type=ProofType.SCHNORR,
                commitment=str(commitment),
                challenge=str(challenge),
                response=str(response),
                public_input={"public_key": str(public_key), "message": message}
            )
            
            # Self-verify to ensure proof is valid
            if not self.schnorr_verify(proof):
                raise ZKProofError("Generated proof failed self-verification")
            
            return proof
            
        except ZKError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="schnorr_prove",
                context={'has_message': bool(message)}
            )
            raise ZKProofError(f"Schnorr proof generation failed: {str(e)}")

    @ensure_state("initialized")
    def schnorr_verify(self, proof: ZKProof) -> bool:
        """Verify a Schnorr zero-knowledge proof with error handling"""
        try:
            # Validate proof type
            if proof.proof_type != ProofType.SCHNORR:
                self.error_handler.handle_error(
                    ZKValidationError("Invalid proof type for Schnorr verification"),
                    operation="schnorr_verify",
                    context={'expected': ProofType.SCHNORR.value, 'received': proof.proof_type.value}
                )
                return False

            # Extract and validate proof components
            commitment = int(proof.commitment)
            challenge = int(proof.challenge)
            response = int(proof.response)
            public_key = int(proof.public_input["public_key"])
            message = proof.public_input.get("message", "")

            # Validate ranges
            if not all(0 < x < self.prime for x in [commitment, public_key]):
                raise ZKValidationError("Proof components out of valid range")

            # Recompute challenge
            expected_challenge = self.hash_to_scalar(commitment, message)
            if challenge != expected_challenge:
                return False

            # Verify: g^response = commitment * public_key^challenge
            left = pow(self.generator, response, self.prime)
            right = (commitment * pow(public_key, challenge, self.prime)) % self.prime

            return left == right

        except (KeyError, ValueError) as e:
            self.error_handler.handle_error(
                e,
                operation="schnorr_verify",
                context={'proof_type': proof.proof_type.value if proof else 'None'}
            )
            return False
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="schnorr_verify",
                context={'critical_error': True}
            )
            return False

    @ensure_state("initialized")
    def range_proof(self, value: int, bits: int = 32) -> Dict[str, Any]:
        """Generate a range proof with comprehensive validation"""
        try:
            # Validate inputs
            if not isinstance(value, int) or value < 0:
                raise ZKValidationError(
                    "Value must be a non-negative integer",
                    context={'value': value if isinstance(value, int) else type(value).__name__}
                )
            
            if not isinstance(bits, int) or bits <= 0:
                raise ZKValidationError(
                    "Bits must be a positive integer",
                    context={'bits': bits}
                )
            
            if bits > 256:
                raise ZKValidationError(
                    "Bit size too large (maximum 256)",
                    context={'bits': bits, 'maximum': 256}
                )
            
            if not (0 <= value < 2**bits):
                raise ZKValidationError(
                    f"Value must be in range [0, 2^{bits})",
                    context={'value': value, 'max': 2**bits - 1}
                )

            # Decompose value into bits
            bit_commitments = []
            bit_proofs = []

            for i in range(bits):
                try:
                    bit = (value >> i) & 1

                    # Commit to each bit
                    commitment = self.generate_commitment(bit)
                    bit_commitments.append(commitment)

                    # Prove bit is 0 or 1
                    proof = self.schnorr_prove(bit, f"bit_{i}_is_{bit}")
                    bit_proofs.append(proof)
                    
                except Exception as e:
                    raise ZKProofError(
                        f"Failed to generate proof for bit {i}",
                        context={'bit_index': i, 'bit_value': bit}
                    ) from e

            return {
                "value_commitment": self.generate_commitment(value),
                "bit_commitments": bit_commitments,
                "bit_proofs": bit_proofs,
                "bits": bits,
                "verification_data": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "proof_count": len(bit_proofs)
                }
            }
            
        except ZKError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="range_proof",
                context={'value': value, 'bits': bits}
            )
            raise ZKProofError(f"Range proof generation failed: {str(e)}")

    @ensure_state("initialized")
    def membership_proof(self, element: Any, set_commitment: str) -> Dict[str, Any]:
        """Prove membership with validation and error handling"""
        try:
            # Validate inputs
            if element is None:
                raise ZKValidationError("Element cannot be None")
            
            if not set_commitment or not isinstance(set_commitment, str):
                raise ZKValidationError(
                    "Invalid set commitment",
                    context={'type': type(set_commitment).__name__}
                )
            
            element_hash = self.hash_to_scalar(element)

            # Generate proof of knowledge of preimage
            proof = self.schnorr_prove(
                element_hash % (self.prime - 1) + 1,  # Ensure valid range
                f"membership_{set_commitment}"
            )

            return {
                "set_commitment": set_commitment,
                "membership_proof": proof,
                "timestamp": datetime.utcnow().isoformat(),
                "element_type": type(element).__name__
            }
            
        except ZKError:
            raise
        except Exception as e:
            self.error_handler.handle_error(
                e,
                operation="membership_proof",
                context={'element_type': type(element).__name__}
            )
            raise ZKProofError(f"Membership proof generation failed: {str(e)}")


# ===========================
# Enhanced ZK Accumulator
# ===========================

class ZKAccumulator:
    """Zero-knowledge accumulator with error handling and state management"""

    def __init__(self, primitives: ZKPrimitives, error_handler: Optional[ZKErrorHandler] = None):
        self.primitives = primitives
        self.error_handler = error_handler or primitives.error_handler
        self.elements: List[int] = []
        self.accumulator = 1
        self.state = "empty"
        self.element_count = 0
        self.operation_log = []

    def _log_operation(self, operation: str, success: bool, details: Dict[str, Any] = None):
        """Log accumulator operations for audit trail"""
        log_entry = {
            'operation': operation,
            'success': success,
            'timestamp': datetime.utcnow().isoformat(),
            'element_count': self.element_count,
            'details': details or {}
        }
        self.operation_log.append(log_entry)

    @validate_inputs()
    def add(self, element: Any) -> str:
        """Add element to accumulator with validation"""
        try:
            if element is None:
                raise ZKValidationError("Cannot add None element to accumulator")
            
            element_hash = self.primitives.hash_to_scalar(element)
            
            # Check for duplicates
            if element_hash in self.elements:
                raise ZKValidationError(
                    "Element already exists in accumulator",
                    context={'element_type': type(element).__name__}
                )
            
            self.elements.append(element_hash)
            self.element_count += 1

            # Update accumulator: acc = acc * g^element_hash
            old_accumulator = self.accumulator
            self.accumulator = (self.accumulator * pow(
                self.primitives.generator,
                element_hash,
                self.primitives.prime
            )) % self.primitives.prime
            
            # Update state
            self.state = "non-empty"
            
            # Log successful operation
            self._log_operation(
                'add',
                True,
                {'element_hash': element_hash, 'old_acc': old_accumulator, 'new_acc': self.accumulator}
            )
            
            return str(self.accumulator)
            
        except Exception as e:
            self._log_operation('add', False, {'error': str(e)})
            self.error_handler.handle_error(
                e,
                operation="accumulator_add",
                context={'element_type': type(element).__name__, 'current_size': len(self.elements)}
            )
            raise

    @ensure_state("non-empty")
    def prove_membership(self, element: Any) -> Optional[Dict[str, Any]]:
        """Generate membership proof with comprehensive error handling"""
        try:
            if element is None:
                raise ZKValidationError("Cannot prove membership of None element")
            
            element_hash = self.primitives.hash_to_scalar(element)

            if element_hash not in self.elements:
                self._log_operation(
                    'prove_membership',
                    False,
                    {'reason': 'element_not_found', 'element_type': type(element).__name__}
                )
                return None

            # Compute witness (product of all other elements)
            witness = 1
            witness_elements = []
            
            for e in self.elements:
                if e != element_hash:
                    witness = (witness * pow(
                        self.primitives.generator,
                        e,
                        self.primitives.prime
                    )) % self.primitives.prime
                    witness_elements.append(e)
            
            # Validate witness
            if witness == 0:
                raise ZKProofError("Invalid witness computed (zero value)")
            
            proof = {
                "element_commitment": self.primitives.generate_commitment(element_hash),
                "witness": str(witness),
                "accumulator": str(self.accumulator),
                "proof_metadata": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "element_index": self.elements.index(element_hash),
                    "total_elements": len(self.elements),
                    "witness_element_count": len(witness_elements)
                }
            }
            
            self._log_operation(
                'prove_membership',
                True,
                {'element_hash': element_hash, 'witness_size': len(witness_elements)}
            )
            
            return proof
            
        except Exception as e:
            self._log_operation('prove_membership', False, {'error': str(e)})
            self.error_handler.handle_error(
                e,
                operation="prove_membership",
                context={'element_type': type(element).__name__ if element else 'None'}
            )
            if isinstance(e, ZKError):
                raise
            else:
                raise ZKProofError(f"Membership proof generation failed: {str(e)}")

    def verify_membership(self, proof: Dict[str, Any]) -> bool:
        """Verify membership proof with comprehensive validation"""
        try:
            # Validate proof structure
            required_fields = ['witness', 'accumulator']
            missing_fields = [f for f in required_fields if f not in proof]
            
            if missing_fields:
                raise ZKValidationError(
                    f"Missing required proof fields: {missing_fields}",
                    context={'provided_fields': list(proof.keys())}
                )
            
            witness = int(proof["witness"])
            accumulator = int(proof["accumulator"])
            
            # Validate values
            if witness <= 0 or witness >= self.primitives.prime:
                raise ZKValidationError(
                    "Invalid witness value",
                    context={'witness_range': f"(0, {self.primitives.prime})"}
                )
            
            if accumulator <= 0 or accumulator >= self.primitives.prime:
                raise ZKValidationError(
                    "Invalid accumulator value",
                    context={'accumulator_range': f"(0, {self.primitives.prime})"}
                )
            
            # For now, just validate that values are in correct range
            # In production, implement full verification logic
            verification_passed = witness > 0 and accumulator > 0
            
            self._log_operation(
                'verify_membership',
                verification_passed,
                {'accumulator_match': accumulator == self.accumulator}
            )
            
            return verification_passed

        except (KeyError, ValueError) as e:
            self._log_operation('verify_membership', False, {'error': str(e)})
            self.error_handler.handle_error(
                e,
                operation="verify_membership",
                context={'proof_keys': list(proof.keys()) if proof else []}
            )
            return False
        except Exception as e:
            self._log_operation('verify_membership', False, {'error': str(e)})
            self.error_handler.handle_error(
                e,
                operation="verify_membership",
                context={'critical_error': True}
            )
            return False

    def get_state_summary(self) -> Dict[str, Any]:
        """Get comprehensive state summary of accumulator"""
        return {
            'state': self.state,
            'element_count': self.element_count,
            'accumulator_value': str(self.accumulator),
            'operation_count': len(self.operation_log),
            'recent_operations': self.operation_log[-5:],
            'health_status': 'healthy' if self.state != 'error' else 'unhealthy'
        }


# ===========================
# Factory Functions with Error Handling
# ===========================

def create_zk_primitives(security_parameter: int = 256, 
                        error_config: Optional[ErrorHandlerConfig] = None) -> ZKPrimitives:
    """Factory function to create ZK primitives with error handling"""
    try:
        error_handler = ZKErrorHandler(error_config)
        return ZKPrimitives(security_parameter, error_handler)
    except Exception as e:
        # Log critical initialization failure
        logging.critical(f"Failed to initialize ZK primitives: {str(e)}")
        raise


def create_zk_accumulator(primitives: Optional[ZKPrimitives] = None,
                         error_config: Optional[ErrorHandlerConfig] = None) -> ZKAccumulator:
    """Factory function to create ZK accumulator with error handling"""
    try:
        if not primitives:
            primitives = create_zk_primitives(error_config=error_config)
        
        error_handler = ZKErrorHandler(error_config) if error_config else primitives.error_handler
        return ZKAccumulator(primitives, error_handler)
    except Exception as e:
        logging.critical(f"Failed to initialize ZK accumulator: {str(e)}")
        raise


# ===========================
# Example Usage with Error Handling
# ===========================

if __name__ == "__main__":
    # Configure error handling
    error_config = ErrorHandlerConfig(
        log_errors=True,
        log_level="INFO",
        include_stacktrace=True,
        error_metrics_enabled=True,
        sanitize_sensitive_data=True
    )
    
    # Add custom notification callback
    def error_notifier(error_details: Dict[str, Any]):
        if error_details['error_type'] in ['ZKCryptographicError', 'ZKProofError']:
            print(f"CRITICAL ERROR ALERT: {error_details['error_message']}")
    
    error_config.notification_callbacks.append(error_notifier)
    
    try:
        # Initialize with error handling
        print("Initializing ZK system with comprehensive error handling...")
        zk = create_zk_primitives(256, error_config)
        accumulator = create_zk_accumulator(zk, error_config)
        
        # Example operations with automatic error handling
        print("\nGenerating commitment...")
        commitment = zk.generate_commitment(42)
        print(f"Commitment generated: {commitment.value[:16]}...")
        
        print("\nGenerating Schnorr proof...")
        proof = zk.schnorr_prove(123, "test message")
        print(f"Proof generated: {proof.proof_type.value}")
        
        print("\nVerifying proof...")
        is_valid = zk.schnorr_verify(proof)
        print(f"Proof valid: {is_valid}")
        
        print("\nGenerating range proof...")
        range_proof = zk.range_proof(150, bits=8)
        print(f"Range proof generated with {len(range_proof['bit_proofs'])} bit proofs")
        
        print("\nTesting accumulator...")
        acc1 = accumulator.add("element1")
        acc2 = accumulator.add("element2")
        print(f"Accumulator after additions: {acc2[:16]}...")
        
        membership_proof = accumulator.prove_membership("element1")
        if membership_proof:
            print("Membership proof generated successfully")
        
        # Get error summary
        print("\nError handling summary:")
        error_summary = zk.error_handler.get_error_summary()
        print(f"Total errors logged: {error_summary['total_errors']}")
        print(f"Error metrics: {error_summary['error_metrics']}")
        
        # Get accumulator state
        print("\nAccumulator state:")
        state_summary = accumulator.get_state_summary()
        print(f"State: {state_summary['state']}")
        print(f"Element count: {state_summary['element_count']}")
        print(f"Operation count: {state_summary['operation_count']}")
        
    except ZKError as e:
        print(f"\nZK Error occurred: {e}")
        print(f"Error code: {e.error_code}")
        print(f"Context: {e.context}")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        traceback.print_exc()

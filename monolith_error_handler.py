"""
ZKAEDI Monolith Error Handling Framework
========================================
A comprehensive error handling system for the ZKAEDI/Cloudflare AI monolithic toolset.
Provides modular, extensible error tracking with detailed logging and recovery mechanisms.
"""

import sys
import json
import time
import traceback
import logging
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
import asyncio


# Error Categories based on the monolith components
class ErrorCategory(Enum):
    TYPE_SYSTEM = auto()      # Foundation of Types errors
    ITERATOR = auto()         # Iterator/Loop errors
    CONTAINER = auto()        # Container operation errors
    METACLASS = auto()        # Metaclass and type errors
    CONTEXT = auto()          # Context manager errors
    FUNCTIONAL = auto()       # Functional programming errors
    OBSERVABILITY = auto()    # Monitoring/HUD errors
    TRUST_DRIFT = auto()      # Trust calibration errors
    EDGE_SYNC = auto()        # Cloudflare edge sync errors
    AGENT = auto()            # Agent operation errors
    NETWORK = auto()          # Network/API errors
    VALIDATION = auto()       # Data validation errors
    SECURITY = auto()         # Security/ZK errors


# Error Severity Levels
class ErrorSeverity(Enum):
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    APOCALYPTIC = 6  # When the monolith faces entropy


@dataclass(frozen=True)
class ErrorContext:
    """Immutable error context following the DataCore pattern"""
    timestamp: float
    category: ErrorCategory
    severity: ErrorSeverity
    component: str
    operation: str
    error_type: str
    message: str
    stack_trace: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    trust_impact: float = 0.0  # Impact on trust drift
    recovery_attempted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'timestamp': self.timestamp,
            'category': self.category.name,
            'severity': self.severity.name,
            'component': self.component,
            'operation': self.operation,
            'error_type': self.error_type,
            'message': self.message,
            'stack_trace': self.stack_trace,
            'metadata': self.metadata,
            'trust_impact': self.trust_impact,
            'recovery_attempted': self.recovery_attempted
        }


class ZkaediException(Exception):
    """Base exception class for all ZKAEDI monolith errors"""

    def __init__(self, message: str, category: ErrorCategory,
                 severity: ErrorSeverity = ErrorSeverity.ERROR,
                 metadata: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.category = category
        self.severity = severity
        self.metadata = metadata or {}
        self.timestamp = time.time()

    @classmethod
    def from_base(cls, base_exception: Exception, category: ErrorCategory = ErrorCategory.TYPE_SYSTEM):
        """Create ZkaediException from standard exception"""
        return cls(
            message=str(base_exception),
            category=category,
            metadata={'original_type': type(base_exception).__name__}
        )


class ErrorHandleManager:
    """
    Six-tiered escalation error handler as mentioned in Chapter V.
    Manages all error handling, logging, and recovery for the monolith.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.error_history = deque(
            maxlen=self.config.get('history_size', 10000))
        self.error_stats = defaultdict(lambda: {'count': 0, 'last_seen': None})
        self.recovery_strategies: Dict[ErrorCategory,
                                       List[Callable]] = defaultdict(list)
        self.trust_state = {'current': 100.0, 'drift': 0.0}
        self._setup_logging()
        self._register_default_strategies()

    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for the error handler"""
        return {
            'history_size': 10000,
            'log_level': logging.INFO,
            'enable_edge_sync': True,
            'trust_threshold': 50.0,
            'escalation_levels': {
                1: {'name': 'monitor', 'action': 'log'},
                2: {'name': 'alert', 'action': 'notify'},
                3: {'name': 'intervene', 'action': 'auto_recover'},
                4: {'name': 'escalate', 'action': 'manual_intervention'},
                5: {'name': 'critical', 'action': 'circuit_break'},
                6: {'name': 'apocalyptic', 'action': 'full_shutdown'}
            }
        }

    def _setup_logging(self):
        """Configure structured logging for the monolith"""
        self.logger = logging.getLogger('ZKAEDI_MONOLITH')
        self.logger.setLevel(self.config['log_level'])

        # Console handler with formatting
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter(
                '[%(asctime)s] %(name)s - %(levelname)s - %(message)s'
            )
        )
        self.logger.addHandler(console_handler)

        # File handler for persistent logs
        file_handler = logging.FileHandler('zkaedi_errors.log')
        file_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s|%(name)s|%(levelname)s|%(message)s'
            )
        )
        self.logger.addHandler(file_handler)

    def _register_default_strategies(self):
        """Register default recovery strategies for each error category"""
        # Type System errors - attempt type coercion
        self.register_recovery(ErrorCategory.TYPE_SYSTEM,
                               self._recover_type_error)

        # Iterator errors - break infinite loops
        self.register_recovery(ErrorCategory.ITERATOR,
                               self._recover_iterator_error)

        # Container errors - validate and repair data structures
        self.register_recovery(ErrorCategory.CONTAINER,
                               self._recover_container_error)

        # Trust drift errors - recalibrate trust
        self.register_recovery(ErrorCategory.TRUST_DRIFT,
                               self._recover_trust_drift)

        # Network errors - retry with exponential backoff
        self.register_recovery(ErrorCategory.NETWORK,
                               self._recover_network_error)

    def handle_error(self, error: Exception, component: str, operation: str,
                     category: Optional[ErrorCategory] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> ErrorContext:
        """
        Main error handling method with six-tiered escalation.
        Returns ErrorContext with full error details.
        """
        # Determine category if not provided
        if category is None:
            category = self._categorize_error(error)

        # Extract severity from error or determine based on category
        severity = self._determine_severity(error, category)

        # Create error context
        error_context = ErrorContext(
            timestamp=time.time(),
            category=category,
            severity=severity,
            component=component,
            operation=operation,
            error_type=type(error).__name__,
            message=str(error),
            stack_trace=traceback.format_exc(),
            metadata=metadata or {},
            trust_impact=self._calculate_trust_impact(category, severity)
        )

        # Log the error
        self._log_error(error_context)

        # Update statistics
        self._update_stats(error_context)

        # Store in history
        self.error_history.append(error_context)

        # Update trust state
        self._update_trust_state(error_context)

        # Attempt recovery based on escalation level
        recovery_attempted = self._attempt_recovery(error_context)

        # Create final context with recovery status
        final_context = ErrorContext(
            **{k: v for k, v in error_context.__dict__.items() if k != 'recovery_attempted'},
            recovery_attempted=recovery_attempted
        )

        # Escalate if necessary
        self._escalate(final_context)

        return final_context

    def _categorize_error(self, error: Exception) -> ErrorCategory:
        """Categorize error based on type and content"""
        error_type_map = {
            TypeError: ErrorCategory.TYPE_SYSTEM,
            ValueError: ErrorCategory.VALIDATION,
            KeyError: ErrorCategory.CONTAINER,
            AttributeError: ErrorCategory.METACLASS,
            RuntimeError: ErrorCategory.AGENT,
            ConnectionError: ErrorCategory.NETWORK,
            TimeoutError: ErrorCategory.EDGE_SYNC,
            AssertionError: ErrorCategory.VALIDATION,
            NotImplementedError: ErrorCategory.FUNCTIONAL,
        }

        return error_type_map.get(type(error), ErrorCategory.TYPE_SYSTEM)

    def _determine_severity(self, error: Exception, category: ErrorCategory) -> ErrorSeverity:
        """Determine error severity based on error type and category"""
        # Check if it's a ZkaediException with explicit severity
        if isinstance(error, ZkaediException):
            return error.severity

        # Severity mapping based on category and error type
        severity_map = {
            ErrorCategory.SECURITY: ErrorSeverity.CRITICAL,
            ErrorCategory.TRUST_DRIFT: ErrorSeverity.ERROR,
            ErrorCategory.METACLASS: ErrorSeverity.ERROR,
            ErrorCategory.NETWORK: ErrorSeverity.WARNING,
            ErrorCategory.VALIDATION: ErrorSeverity.WARNING,
        }

        return severity_map.get(category, ErrorSeverity.ERROR)

    def _calculate_trust_impact(self, category: ErrorCategory, severity: ErrorSeverity) -> float:
        """Calculate impact on trust drift based on error category and severity"""
        base_impact = {
            ErrorSeverity.DEBUG: 0.0,
            ErrorSeverity.INFO: 0.0,
            ErrorSeverity.WARNING: -0.5,
            ErrorSeverity.ERROR: -2.0,
            ErrorSeverity.CRITICAL: -5.0,
            ErrorSeverity.APOCALYPTIC: -20.0
        }

        category_multiplier = {
            ErrorCategory.TRUST_DRIFT: 2.0,
            ErrorCategory.SECURITY: 3.0,
            ErrorCategory.AGENT: 1.5,
            ErrorCategory.EDGE_SYNC: 1.2
        }

        impact = base_impact.get(severity, -1.0)
        multiplier = category_multiplier.get(category, 1.0)

        return impact * multiplier

    def _update_trust_state(self, error_context: ErrorContext):
        """Update the monolith's trust state based on error impact"""
        self.trust_state['current'] += error_context.trust_impact
        self.trust_state['drift'] = error_context.trust_impact

        # Ensure trust doesn't go below 0 or above 100
        self.trust_state['current'] = max(
            0.0, min(100.0, self.trust_state['current']))

        # Trigger trust drift recovery if below threshold
        if self.trust_state['current'] < self.config['trust_threshold']:
            self.logger.warning(
                f"Trust level critical: {self.trust_state['current']}")
            self._trigger_trust_recovery()

    def _log_error(self, error_context: ErrorContext):
        """Log error with appropriate level and structured format"""
        log_level_map = {
            ErrorSeverity.DEBUG: logging.DEBUG,
            ErrorSeverity.INFO: logging.INFO,
            ErrorSeverity.WARNING: logging.WARNING,
            ErrorSeverity.ERROR: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL,
            ErrorSeverity.APOCALYPTIC: logging.CRITICAL
        }

        log_level = log_level_map.get(error_context.severity, logging.ERROR)

        log_message = (
            f"[{error_context.category.name}] "
            f"{error_context.component}.{error_context.operation} - "
            f"{error_context.error_type}: {error_context.message}"
        )

        self.logger.log(log_level, log_message, extra={
            'error_context': error_context.to_dict()
        })

    def _update_stats(self, error_context: ErrorContext):
        """Update error statistics for monitoring"""
        key = f"{error_context.category.name}:{error_context.error_type}"
        self.error_stats[key]['count'] += 1
        self.error_stats[key]['last_seen'] = error_context.timestamp

    def _attempt_recovery(self, error_context: ErrorContext) -> bool:
        """Attempt to recover from error using registered strategies"""
        strategies = self.recovery_strategies.get(error_context.category, [])

        for strategy in strategies:
            try:
                if strategy(error_context, self):
                    self.logger.info(
                        f"Recovery successful for {error_context.category.name}")
                    return True
            except Exception as e:
                self.logger.error(f"Recovery strategy failed: {e}")

        return False

    def _escalate(self, error_context: ErrorContext):
        """Escalate error based on severity and configured escalation levels"""
        escalation_level = min(error_context.severity.value, 6)
        escalation_config = self.config['escalation_levels'].get(
            escalation_level)

        if not escalation_config:
            return

        action = escalation_config['action']

        if action == 'notify':
            self._send_notification(error_context)
        elif action == 'auto_recover':
            self._auto_recover(error_context)
        elif action == 'manual_intervention':
            self._request_manual_intervention(error_context)
        elif action == 'circuit_break':
            self._circuit_break(error_context)
        elif action == 'full_shutdown':
            self._emergency_shutdown(error_context)

    # Recovery Strategy Methods
    def _recover_type_error(self, error_context: ErrorContext, handler: 'ErrorHandleManager') -> bool:
        """Attempt to recover from type system errors"""
        # Implementation would attempt type coercion or provide default values
        return False

    def _recover_iterator_error(self, error_context: ErrorContext, handler: 'ErrorHandleManager') -> bool:
        """Break infinite loops and recover iterator state"""
        # Implementation would set loop limits or break conditions
        return False

    def _recover_container_error(self, error_context: ErrorContext, handler: 'ErrorHandleManager') -> bool:
        """Validate and repair container data structures"""
        # Implementation would validate data integrity and repair if possible
        return False

    def _recover_trust_drift(self, error_context: ErrorContext, handler: 'ErrorHandleManager') -> bool:
        """Recalibrate trust levels"""
        handler.trust_state['current'] = min(
            100.0, handler.trust_state['current'] + 10.0)
        handler.trust_state['drift'] = 0.0
        return True

    def _recover_network_error(self, error_context: ErrorContext, handler: 'ErrorHandleManager') -> bool:
        """Retry network operations with exponential backoff"""
        # Implementation would retry with backoff strategy
        return False

    def _trigger_trust_recovery(self):
        """Initiate trust recovery process"""
        self.logger.info("Initiating trust recovery protocol")
        # Implementation would trigger trust recalibration

    def _send_notification(self, error_context: ErrorContext):
        """Send notifications for escalated errors"""
        # Implementation would send to configured notification channels
        pass

    def _auto_recover(self, error_context: ErrorContext):
        """Attempt automatic recovery for moderate errors"""
        # Implementation would trigger automated recovery procedures
        pass

    def _request_manual_intervention(self, error_context: ErrorContext):
        """Request manual intervention for critical errors"""
        self.logger.critical(
            f"Manual intervention required: {error_context.message}")
        # Implementation would alert operators

    def _circuit_break(self, error_context: ErrorContext):
        """Implement circuit breaker pattern for critical failures"""
        self.logger.critical(
            f"Circuit breaker activated for {error_context.component}")
        # Implementation would disable affected components

    def _emergency_shutdown(self, error_context: ErrorContext):
        """Emergency shutdown for apocalyptic errors"""
        self.logger.critical(
            "APOCALYPTIC ERROR - INITIATING EMERGENCY SHUTDOWN")
        # Implementation would gracefully shutdown the monolith

    # Public API Methods
    def register_recovery(self, category: ErrorCategory, strategy: Callable) -> None:
        """Register a recovery strategy for a specific error category"""
        self.recovery_strategies[category].append(strategy)

    def get_error_stats(self) -> Dict[str, Any]:
        """Get current error statistics"""
        return dict(self.error_stats)

    def get_trust_state(self) -> Dict[str, float]:
        """Get current trust state"""
        return self.trust_state.copy()

    def get_recent_errors(self, limit: int = 100) -> List[ErrorContext]:
        """Get recent errors from history"""
        return list(self.error_history)[-limit:]

    @contextmanager
    def trust_lock(self):
        """Context manager for trust-critical operations"""
        initial_trust = self.trust_state['current']
        try:
            yield
        except Exception as e:
            # Handle error within trust context
            self.handle_error(e, 'trust_lock', 'context_operation',
                              ErrorCategory.TRUST_DRIFT)
            raise
        finally:
            # Log trust delta
            trust_delta = self.trust_state['current'] - initial_trust
            if trust_delta != 0:
                self.logger.info(f"Trust delta: {trust_delta:+.2f}")


# Decorator for automatic error handling
def zkaedi_error_handler(category: ErrorCategory = ErrorCategory.TYPE_SYSTEM,
                         component: str = 'unknown'):
    """Decorator for automatic error handling in monolith methods"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            error_manager = kwargs.get('error_manager') or ErrorHandleManager()
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_manager.handle_error(
                    error=e,
                    component=component,
                    operation=func.__name__,
                    category=category,
                    metadata={'args': str(args), 'kwargs': str(kwargs)}
                )
                raise
        return wrapper
    return decorator


# Async error handling support
class AsyncErrorHandleManager(ErrorHandleManager):
    """Async version of ErrorHandleManager for edge operations"""

    async def handle_error_async(self, error: Exception, component: str, operation: str,
                                 category: Optional[ErrorCategory] = None,
                                 metadata: Optional[Dict[str, Any]] = None) -> ErrorContext:
        """Async error handling with edge sync capabilities"""
        # Create error context synchronously
        error_context = await asyncio.get_event_loop().run_in_executor(
            None,
            super().handle_error,
            error, component, operation, category, metadata
        )

        # Sync to edge if enabled
        if self.config.get('enable_edge_sync'):
            await self._sync_to_edge(error_context)

        return error_context

    async def _sync_to_edge(self, error_context: ErrorContext):
        """Sync error to Cloudflare edge"""
        # Implementation would sync to Cloudflare D1/R2
        pass


# Example usage demonstrating the monolith error handling
if __name__ == "__main__":
    # Initialize the error handler
    error_manager = ErrorHandleManager({
        'log_level': logging.DEBUG,
        'trust_threshold': 60.0
    })

    # Example: Type system error
    try:
        # Simulating a type error in the monolith
        result = int("not_a_number")
    except ValueError as e:
        context = error_manager.handle_error(
            error=e,
            component="TypeSystem",
            operation="cast_int",
            category=ErrorCategory.TYPE_SYSTEM
        )
        print(f"Error handled: {context.message}")

    # Example: Using the decorator
    @zkaedi_error_handler(category=ErrorCategory.AGENT, component="VectorAgent")
    def process_vector(vector: List[float], error_manager=None):
        if not vector:
            raise ValueError("Empty vector provided")
        return sum(vector) / len(vector)

    # Example: Trust-critical operation
    with error_manager.trust_lock():
        # Simulate trust-critical operation
        print(f"Current trust: {error_manager.get_trust_state()['current']}")

    # Get error statistics
    stats = error_manager.get_error_stats()
    print(f"Error statistics: {stats}")

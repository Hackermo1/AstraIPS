#!/usr/bin/env python3
"""
Threading Manager Module
Reusable module for managing concurrent operations in MQTT monitoring
"""

import threading
import time
import queue
import logging
from typing import Callable, Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, Future
import signal
import sys

class ThreadStatus(Enum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    ERROR = "ERROR"
    PAUSED = "PAUSED"

@dataclass
class ThreadInfo:
    name: str
    thread: threading.Thread
    status: ThreadStatus
    start_time: float
    error: Optional[Exception] = None
    result: Any = None

class ThreadingManager:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.threads: Dict[str, ThreadInfo] = {}
        self.thread_pool = ThreadPoolExecutor(max_workers=max_workers)
        self.message_queue = queue.Queue()
        self.running = True
        self.lock = threading.Lock()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.shutdown()

    def start_thread(self, name: str, target: Callable, args: tuple = (), 
                    kwargs: dict = None, daemon: bool = True) -> bool:
        """Start a new thread"""
        if kwargs is None:
            kwargs = {}
        
        with self.lock:
            if name in self.threads:
                self.logger.warning(f"Thread '{name}' already exists")
                return False
            
            def thread_wrapper():
                try:
                    self.logger.info(f"Starting thread '{name}'")
                    result = target(*args, **kwargs)
                    with self.lock:
                        self.threads[name].result = result
                        self.threads[name].status = ThreadStatus.STOPPED
                    self.logger.info(f"Thread '{name}' completed successfully")
                except Exception as e:
                    with self.lock:
                        self.threads[name].error = e
                        self.threads[name].status = ThreadStatus.ERROR
                    self.logger.error(f"Thread '{name}' failed: {e}")
            
            thread = threading.Thread(
                target=thread_wrapper,
                name=name,
                daemon=daemon
            )
            
            self.threads[name] = ThreadInfo(
                name=name,
                thread=thread,
                status=ThreadStatus.RUNNING,
                start_time=time.time()
            )
            
            thread.start()
            return True

    def start_thread_pool_task(self, name: str, target: Callable, 
                              args: tuple = (), kwargs: dict = None) -> Future:
        """Start a task in the thread pool"""
        if kwargs is None:
            kwargs = {}
        
        future = self.thread_pool.submit(target, *args, **kwargs)
        self.logger.info(f"Submitted task '{name}' to thread pool")
        return future

    def stop_thread(self, name: str, timeout: float = 5.0) -> bool:
        """Stop a specific thread"""
        with self.lock:
            if name not in self.threads:
                self.logger.warning(f"Thread '{name}' not found")
                return False
            
            thread_info = self.threads[name]
            if thread_info.status == ThreadStatus.STOPPED:
                return True
            
            thread_info.status = ThreadStatus.STOPPED
            thread_info.thread.join(timeout=timeout)
            
            if thread_info.thread.is_alive():
                self.logger.warning(f"Thread '{name}' did not stop within timeout")
                return False
            
            self.logger.info(f"Thread '{name}' stopped")
            return True

    def stop_all_threads(self, timeout: float = 10.0) -> bool:
        """Stop all threads"""
        self.logger.info("Stopping all threads...")
        
        with self.lock:
            threads_to_stop = list(self.threads.keys())
        
        success = True
        for name in threads_to_stop:
            if not self.stop_thread(name, timeout):
                success = False
        
        return success

    def shutdown(self, timeout: float = 10.0):
        """Shutdown the threading manager"""
        self.logger.info("Shutting down threading manager...")
        self.running = False
        
        # Stop all threads
        self.stop_all_threads(timeout)
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        self.logger.info("Threading manager shutdown complete")

    def get_thread_status(self, name: str) -> Optional[ThreadStatus]:
        """Get status of a specific thread"""
        with self.lock:
            if name in self.threads:
                return self.threads[name].status
            return None

    def get_all_threads_status(self) -> Dict[str, ThreadStatus]:
        """Get status of all threads"""
        with self.lock:
            return {name: info.status for name, info in self.threads.items()}

    def is_thread_alive(self, name: str) -> bool:
        """Check if a thread is alive"""
        with self.lock:
            if name in self.threads:
                return self.threads[name].thread.is_alive()
            return False

    def get_thread_count(self) -> int:
        """Get number of active threads"""
        with self.lock:
            return len([t for t in self.threads.values() if t.status == ThreadStatus.RUNNING])

    def wait_for_thread(self, name: str, timeout: Optional[float] = None) -> Any:
        """Wait for a thread to complete and return its result"""
        with self.lock:
            if name not in self.threads:
                return None
            
            thread_info = self.threads[name]
        
        thread_info.thread.join(timeout=timeout)
        
        if thread_info.thread.is_alive():
            return None
        
        return thread_info.result

    def wait_for_all_threads(self, timeout: Optional[float] = None) -> bool:
        """Wait for all threads to complete"""
        with self.lock:
            threads = list(self.threads.values())
        
        for thread_info in threads:
            thread_info.thread.join(timeout=timeout)
            if thread_info.thread.is_alive():
                return False
        
        return True

    def send_message(self, message: Any):
        """Send a message to the message queue"""
        self.message_queue.put(message)

    def get_message(self, timeout: Optional[float] = None) -> Any:
        """Get a message from the message queue"""
        try:
            return self.message_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def has_messages(self) -> bool:
        """Check if there are messages in the queue"""
        return not self.message_queue.empty()

    def get_queue_size(self) -> int:
        """Get the number of messages in the queue"""
        return self.message_queue.qsize()

    def clear_queue(self):
        """Clear all messages from the queue"""
        while not self.message_queue.empty():
            try:
                self.message_queue.get_nowait()
            except queue.Empty:
                break

    def get_thread_info(self, name: str) -> Optional[ThreadInfo]:
        """Get detailed information about a thread"""
        with self.lock:
            return self.threads.get(name)

    def get_all_threads_info(self) -> Dict[str, ThreadInfo]:
        """Get detailed information about all threads"""
        with self.lock:
            return self.threads.copy()

    def cleanup_finished_threads(self):
        """Remove finished threads from the thread list"""
        with self.lock:
            finished_threads = [
                name for name, info in self.threads.items()
                if not info.thread.is_alive() and info.status in [ThreadStatus.STOPPED, ThreadStatus.ERROR]
            ]
            
            for name in finished_threads:
                del self.threads[name]
                self.logger.info(f"Cleaned up finished thread '{name}'")

    def get_statistics(self) -> Dict[str, Any]:
        """Get threading statistics"""
        with self.lock:
            total_threads = len(self.threads)
            running_threads = len([t for t in self.threads.values() if t.status == ThreadStatus.RUNNING])
            stopped_threads = len([t for t in self.threads.values() if t.status == ThreadStatus.STOPPED])
            error_threads = len([t for t in self.threads.values() if t.status == ThreadStatus.ERROR])
            
            return {
                'total_threads': total_threads,
                'running_threads': running_threads,
                'stopped_threads': stopped_threads,
                'error_threads': error_threads,
                'queue_size': self.get_queue_size(),
                'max_workers': self.max_workers
            }

# Global threading manager instance
_manager = None

def get_manager() -> ThreadingManager:
    """Get global threading manager instance (singleton pattern)"""
    global _manager
    if _manager is None:
        _manager = ThreadingManager()
    return _manager

# Convenience functions
def start_thread(name: str, target: Callable, args: tuple = (), kwargs: dict = None) -> bool:
    """Start a thread using the global manager"""
    return get_manager().start_thread(name, target, args, kwargs)

def stop_thread(name: str, timeout: float = 5.0) -> bool:
    """Stop a thread using the global manager"""
    return get_manager().stop_thread(name, timeout)

def shutdown_all(timeout: float = 10.0):
    """Shutdown all threads using the global manager"""
    get_manager().shutdown(timeout)

# If script is run directly, test the threading manager
if __name__ == "__main__":
    import random
    
    def test_worker(name: str, duration: float):
        """Test worker function"""
        print(f"Worker {name} starting...")
        time.sleep(duration)
        print(f"Worker {name} completed")
        return f"Result from {name}"
    
    def test_error_worker(name: str):
        """Test worker that raises an exception"""
        print(f"Error worker {name} starting...")
        time.sleep(1)
        raise Exception(f"Error in {name}")
    
    # Test the threading manager
    manager = ThreadingManager(max_workers=5)
    
    print("Testing ThreadingManager...")
    
    # Start some test threads
    manager.start_thread("worker1", test_worker, ("worker1", 2.0))
    manager.start_thread("worker2", test_worker, ("worker2", 3.0))
    manager.start_thread("error_worker", test_error_worker, ("error_worker",))
    
    # Start a thread pool task
    future = manager.start_thread_pool_task("pool_task", test_worker, ("pool_task", 1.5))
    
    # Wait a bit
    time.sleep(1)
    
    # Print status
    print(f"Thread status: {manager.get_all_threads_status()}")
    print(f"Statistics: {manager.get_statistics()}")
    
    # Wait for completion
    print("Waiting for threads to complete...")
    manager.wait_for_all_threads(timeout=10)
    
    # Print final status
    print(f"Final status: {manager.get_all_threads_status()}")
    print(f"Final statistics: {manager.get_statistics()}")
    
    # Shutdown
    manager.shutdown()
    print("Test completed")
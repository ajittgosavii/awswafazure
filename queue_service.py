"""
Queue Service - Asynchronous Operations Management
Handles background tasks and long-running operations
"""

import streamlit as st
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import json
import threading
import time
from queue import Queue, Empty
import uuid

class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class Task:
    """Represents a queued task"""
    task_id: str
    task_type: str
    task_name: str
    function: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Any = None
    error: Optional[str] = None
    progress: int = 0
    metadata: Dict = field(default_factory=dict)
    
    def __lt__(self, other):
        """For priority queue sorting"""
        return self.priority.value > other.priority.value


class TaskQueue:
    """Queue for managing asynchronous tasks"""
    
    def __init__(self, max_workers: int = 3):
        """
        Initialize task queue
        
        Args:
            max_workers: Maximum number of concurrent workers
        """
        self.queue = Queue()
        self.tasks: Dict[str, Task] = {}
        self.max_workers = max_workers
        self.workers: List[threading.Thread] = []
        self.running = False
        self.lock = threading.Lock()
    
    def start(self):
        """Start queue workers"""
        if not self.running:
            self.running = True
            for i in range(self.max_workers):
                worker = threading.Thread(target=self._worker, args=(i,), daemon=True)
                worker.start()
                self.workers.append(worker)
    
    def stop(self):
        """Stop queue workers"""
        self.running = False
        for worker in self.workers:
            if worker.is_alive():
                worker.join(timeout=5)
        self.workers.clear()
    
    def _worker(self, worker_id: int):
        """Worker thread that processes tasks"""
        while self.running:
            try:
                # Get task with timeout
                task = self.queue.get(timeout=1)
                
                if task is None:
                    continue
                
                # Update task status
                with self.lock:
                    task.status = TaskStatus.RUNNING
                    task.started_at = datetime.now()
                
                try:
                    # Execute task
                    result = task.function(*task.args, **task.kwargs)
                    
                    # Update task with result
                    with self.lock:
                        task.status = TaskStatus.COMPLETED
                        task.completed_at = datetime.now()
                        task.result = result
                        task.progress = 100
                
                except Exception as e:
                    # Handle error
                    with self.lock:
                        task.status = TaskStatus.FAILED
                        task.completed_at = datetime.now()
                        task.error = str(e)
                
                finally:
                    self.queue.task_done()
            
            except Empty:
                continue
            except Exception as e:
                st.error(f"Worker {worker_id} error: {e}")
    
    def submit_task(
        self,
        task_type: str,
        task_name: str,
        function: Callable,
        args: tuple = (),
        kwargs: dict = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        metadata: Dict = None
    ) -> str:
        """
        Submit a new task to the queue
        
        Args:
            task_type: Type of task (e.g., 'deployment', 'scan', 'backup')
            task_name: Human-readable task name
            function: Function to execute
            args: Positional arguments for function
            kwargs: Keyword arguments for function
            priority: Task priority
            metadata: Additional task metadata
        
        Returns:
            Task ID
        """
        task_id = str(uuid.uuid4())
        
        task = Task(
            task_id=task_id,
            task_type=task_type,
            task_name=task_name,
            function=function,
            args=args,
            kwargs=kwargs or {},
            priority=priority,
            metadata=metadata or {}
        )
        
        with self.lock:
            self.tasks[task_id] = task
        
        self.queue.put(task)
        
        return task_id
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID"""
        with self.lock:
            return self.tasks.get(task_id)
    
    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """Get task status"""
        task = self.get_task(task_id)
        return task.status if task else None
    
    def get_task_result(self, task_id: str) -> Optional[Any]:
        """Get task result (only if completed)"""
        task = self.get_task(task_id)
        if task and task.status == TaskStatus.COMPLETED:
            return task.result
        return None
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending task"""
        with self.lock:
            task = self.tasks.get(task_id)
            if task and task.status == TaskStatus.PENDING:
                task.status = TaskStatus.CANCELLED
                return True
        return False
    
    def get_all_tasks(
        self,
        status: Optional[TaskStatus] = None,
        task_type: Optional[str] = None
    ) -> List[Task]:
        """Get all tasks, optionally filtered"""
        with self.lock:
            tasks = list(self.tasks.values())
        
        if status:
            tasks = [t for t in tasks if t.status == status]
        
        if task_type:
            tasks = [t for t in tasks if t.task_type == task_type]
        
        return sorted(tasks, key=lambda t: t.created_at, reverse=True)
    
    def get_queue_size(self) -> int:
        """Get current queue size"""
        return self.queue.qsize()
    
    def clear_completed_tasks(self, older_than_hours: int = 24):
        """Clear completed tasks older than specified hours"""
        cutoff = datetime.now() - timedelta(hours=older_than_hours)
        
        with self.lock:
            to_remove = [
                task_id for task_id, task in self.tasks.items()
                if task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]
                and task.completed_at and task.completed_at < cutoff
            ]
            
            for task_id in to_remove:
                del self.tasks[task_id]
        
        return len(to_remove)


class BackgroundTaskManager:
    """Manager for common background tasks"""
    
    def __init__(self, queue: TaskQueue):
        """Initialize background task manager"""
        self.queue = queue
    
    def deploy_infrastructure(
        self,
        blueprint_name: str,
        account_id: str,
        region: str,
        parameters: Dict
    ) -> str:
        """Submit infrastructure deployment task"""
        
        def deploy_fn():
            """Actual deployment function"""
            # This would integrate with CloudFormation/Terraform
            time.sleep(5)  # Simulate deployment
            return {
                'status': 'success',
                'stack_id': f'stack-{uuid.uuid4()}',
                'outputs': {}
            }
        
        return self.queue.submit_task(
            task_type='deployment',
            task_name=f'Deploy {blueprint_name} to {account_id}',
            function=deploy_fn,
            priority=TaskPriority.HIGH,
            metadata={
                'blueprint': blueprint_name,
                'account_id': account_id,
                'region': region,
                'parameters': parameters
            }
        )
    
    def security_scan(
        self,
        account_id: str,
        scan_type: str = 'full'
    ) -> str:
        """Submit security scan task"""
        
        def scan_fn():
            """Actual scan function"""
            time.sleep(10)  # Simulate scan
            return {
                'findings_count': 5,
                'critical': 1,
                'high': 2,
                'medium': 2
            }
        
        return self.queue.submit_task(
            task_type='security_scan',
            task_name=f'Security scan for {account_id}',
            function=scan_fn,
            priority=TaskPriority.NORMAL,
            metadata={
                'account_id': account_id,
                'scan_type': scan_type
            }
        )
    
    def cost_analysis(
        self,
        account_id: str,
        start_date: datetime,
        end_date: datetime
    ) -> str:
        """Submit cost analysis task"""
        
        def analyze_fn():
            """Actual analysis function"""
            time.sleep(8)  # Simulate analysis
            return {
                'total_cost': 12345.67,
                'services': {
                    'EC2': 5000,
                    'RDS': 3000,
                    'S3': 500
                },
                'recommendations': [
                    'Right-size EC2 instances',
                    'Enable S3 Intelligent-Tiering'
                ]
            }
        
        return self.queue.submit_task(
            task_type='cost_analysis',
            task_name=f'Cost analysis for {account_id}',
            function=analyze_fn,
            priority=TaskPriority.LOW,
            metadata={
                'account_id': account_id,
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
        )
    
    def backup_resources(
        self,
        account_id: str,
        resource_types: List[str]
    ) -> str:
        """Submit backup task"""
        
        def backup_fn():
            """Actual backup function"""
            time.sleep(15)  # Simulate backup
            return {
                'backed_up': 50,
                'failed': 2,
                'backup_ids': [f'backup-{i}' for i in range(5)]
            }
        
        return self.queue.submit_task(
            task_type='backup',
            task_name=f'Backup resources in {account_id}',
            function=backup_fn,
            priority=TaskPriority.HIGH,
            metadata={
                'account_id': account_id,
                'resource_types': resource_types
            }
        )


# Global instances
@st.cache_resource
def get_task_queue() -> TaskQueue:
    """Get cached task queue instance"""
    queue = TaskQueue(max_workers=3)
    queue.start()
    return queue

@st.cache_resource
def get_background_task_manager() -> BackgroundTaskManager:
    """Get cached background task manager"""
    queue = get_task_queue()
    return BackgroundTaskManager(queue)

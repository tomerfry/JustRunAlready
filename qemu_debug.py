#!/usr/bin/env python3
"""
QEMU Iterative Debugger - Full Featured Version

A comprehensive tool for running embedded executables locally by iteratively
building GDB scripts to overcome failures.

Features:
- Automatic failure detection and analysis
- Smart function hooking with meaningful logging  
- File/library dependency tracking
- Interactive fix suggestions
- Persistent session state
- Comprehensive logging

Usage:
    sudo python3 qemu_debug.py -c /path/to/rootfs -b /usr/bin/service -a arm
"""

import argparse
import json
import os
import re
import select
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional


# ============================================================================
# ANSI Colors and Logging
# ============================================================================

class C:
    """ANSI color codes"""
    H = '\033[95m'      # Header/Purple
    B = '\033[94m'      # Blue
    C = '\033[96m'      # Cyan
    G = '\033[92m'      # Green
    Y = '\033[93m'      # Yellow
    R = '\033[91m'      # Red
    E = '\033[0m'       # End
    BOLD = '\033[1m'
    DIM = '\033[2m'


class Logger:
    """Centralized logging with levels"""
    
    VERBOSE = False
    
    @staticmethod
    def info(msg: str):
        print(f"{C.B}[•]{C.E} {msg}")
    
    @staticmethod
    def ok(msg: str):
        print(f"{C.G}[✓]{C.E} {msg}")
    
    @staticmethod
    def warn(msg: str):
        print(f"{C.Y}[!]{C.E} {msg}")
    
    @staticmethod
    def error(msg: str):
        print(f"{C.R}[✗]{C.E} {msg}")
    
    @staticmethod
    def event(tag: str, msg: str):
        print(f"{C.C}[{tag}]{C.E} {msg}")
    
    @staticmethod
    def debug(msg: str):
        if Logger.VERBOSE:
            print(f"{C.DIM}[DBG] {msg}{C.E}")
    
    @staticmethod
    def hook(func: str, details: str):
        print(f"{C.H}[HOOK]{C.E} {func}{details}")
    
    @staticmethod
    def header(text: str):
        width = 60
        print(f"\n{C.BOLD}{'═'*width}{C.E}")
        print(f"{C.BOLD}{text.center(width)}{C.E}")
        print(f"{C.BOLD}{'═'*width}{C.E}\n")

log = Logger()


# ============================================================================
# Data Classes
# ============================================================================

class FailType(Enum):
    SIGSEGV = auto()
    SIGABRT = auto()
    SIGILL = auto()
    SIGBUS = auto()
    SIGFPE = auto()
    FILE_MISSING = auto()
    LIB_MISSING = auto()
    SYMBOL_MISSING = auto()  # New: undefined symbol
    DEV_ACCESS = auto()
    PERM_DENIED = auto()
    FUNC_FAIL = auto()
    TIMEOUT = auto()
    UNKNOWN = auto()


@dataclass
class Failure:
    """Represents a failure event"""
    type: FailType
    addr: int = 0
    func: str = ""
    regs: dict = field(default_factory=dict)
    bt: list = field(default_factory=list)
    info: dict = field(default_factory=dict)
    
    def __str__(self):
        return f"0x{self.addr:08x} in {self.func or '?'}: {self.type.name}"


@dataclass
class Rule:
    """A GDB rule for handling a specific location"""
    addr: int
    action: str  # skip, ret, set, nop
    ret_val: int = 0
    skip_to: int = 0
    reg_set: dict = field(default_factory=dict)
    comment: str = ""
    enabled: bool = True
    
    def to_gdb(self, arch: dict) -> list[str]:
        """Convert to GDB commands"""
        cmds = [f"# {self.comment}" if self.comment else f"# Rule at 0x{self.addr:08x}"]
        
        if not self.enabled:
            cmds[0] = "# [DISABLED] " + cmds[0][2:]
            return cmds
        
        cmds.append(f"break *0x{self.addr:08x}")
        cmds.append("commands")
        cmds.append("  silent")
        
        if self.action == 'skip':
            cmds.append(f"  set $pc = 0x{self.skip_to:08x}")
        elif self.action == 'ret':
            cmds.append(f"  set ${arch['ret']} = {self.ret_val}")
            cmds.append(f"  set $pc = ${arch['lr']}")
        elif self.action == 'set':
            for r, v in self.reg_set.items():
                cmds.append(f"  set ${r} = {v}")
        
        cmds.append("  continue")
        cmds.append("end")
        return cmds


@dataclass
class Hook:
    """A logging hook for a function"""
    addr: int
    name: str
    fmt: str
    args: list = field(default_factory=list)  # [(reg, type), ...]
    enabled: bool = True
    
    def to_gdb(self) -> list[str]:
        """Convert to GDB commands"""
        if not self.enabled:
            return [f"# [DISABLED] Hook: {self.name}"]
        
        cmds = [
            f"# Hook: {self.name}",
            f"break *0x{self.addr:08x}",
            "commands",
            "  silent",
        ]
        
        if self.args:
            arg_str = ", ".join(f"${a[0]}" for a in self.args)
            cmds.append(f'  printf "[H] {self.fmt}\\n", {arg_str}')
        else:
            cmds.append(f'  printf "[H] {self.name}()\\n"')
        
        cmds.extend(["  continue", "end"])
        return cmds


# ============================================================================
# Architecture Configurations
# ============================================================================

ARCHS = {
    'arm': {
        'qemu': 'qemu-arm-static',
        'gdb': 'gdb-multiarch',
        'pc': 'pc', 'ret': 'r0', 'lr': 'lr', 'sp': 'sp',
        'args': ['r0', 'r1', 'r2', 'r3'],
        'insn_size': 4,
    },
    'arm64': {
        'qemu': 'qemu-aarch64-static',
        'gdb': 'gdb-multiarch',
        'pc': 'pc', 'ret': 'x0', 'lr': 'x30', 'sp': 'sp',
        'args': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
        'insn_size': 4,
    },
    'mips': {
        'qemu': 'qemu-mips-static',
        'gdb': 'gdb-multiarch',
        'pc': 'pc', 'ret': 'v0', 'lr': 'ra', 'sp': 'sp',
        'args': ['a0', 'a1', 'a2', 'a3'],
        'insn_size': 4,
    },
    'mipsel': {
        'qemu': 'qemu-mipsel-static',
        'gdb': 'gdb-multiarch',
        'pc': 'pc', 'ret': 'v0', 'lr': 'ra', 'sp': 'sp',
        'args': ['a0', 'a1', 'a2', 'a3'],
        'insn_size': 4,
    },
    'ppc': {
        'qemu': 'qemu-ppc-static',
        'gdb': 'gdb-multiarch',
        'pc': 'pc', 'ret': 'r3', 'lr': 'lr', 'sp': 'r1',
        'args': ['r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10'],
        'insn_size': 4,
    },
}


# ============================================================================
# Known Functions Database
# ============================================================================

FUNCS = {
    # File I/O
    'open':     {'ret': -1, 'fmt': 'open("%s", 0x%x)', 'args': [('r0', 's'), ('r1', 'x')]},
    'open64':   {'ret': -1, 'fmt': 'open64("%s", 0x%x)', 'args': [('r0', 's'), ('r1', 'x')]},
    'fopen':    {'ret': 0,  'fmt': 'fopen("%s", "%s")', 'args': [('r0', 's'), ('r1', 's')]},
    'fopen64':  {'ret': 0,  'fmt': 'fopen64("%s", "%s")', 'args': [('r0', 's'), ('r1', 's')]},
    'close':    {'ret': 0,  'fmt': 'close(%d)', 'args': [('r0', 'd')]},
    'read':     {'ret': -1, 'fmt': 'read(%d, 0x%x, %d)', 'args': [('r0', 'd'), ('r1', 'x'), ('r2', 'd')]},
    'write':    {'ret': -1, 'fmt': 'write(%d, 0x%x, %d)', 'args': [('r0', 'd'), ('r1', 'x'), ('r2', 'd')]},
    'access':   {'ret': -1, 'fmt': 'access("%s", %d)', 'args': [('r0', 's'), ('r1', 'd')]},
    'stat':     {'ret': -1, 'fmt': 'stat("%s", ...)', 'args': [('r0', 's')]},
    'stat64':   {'ret': -1, 'fmt': 'stat64("%s", ...)', 'args': [('r0', 's')]},
    'lstat':    {'ret': -1, 'fmt': 'lstat("%s", ...)', 'args': [('r0', 's')]},
    'fstat':    {'ret': -1, 'fmt': 'fstat(%d, ...)', 'args': [('r0', 'd')]},
    'opendir':  {'ret': 0,  'fmt': 'opendir("%s")', 'args': [('r0', 's')]},
    'readdir':  {'ret': 0,  'fmt': 'readdir(0x%x)', 'args': [('r0', 'x')]},
    'mkdir':    {'ret': -1, 'fmt': 'mkdir("%s", %o)', 'args': [('r0', 's'), ('r1', 'o')]},
    'unlink':   {'ret': -1, 'fmt': 'unlink("%s")', 'args': [('r0', 's')]},
    'rename':   {'ret': -1, 'fmt': 'rename("%s", "%s")', 'args': [('r0', 's'), ('r1', 's')]},
    
    # Memory
    'mmap':     {'ret': -1, 'fmt': 'mmap(0x%x, %d, 0x%x, 0x%x)', 'args': [('r0', 'x'), ('r1', 'd'), ('r2', 'x'), ('r3', 'x')]},
    'mmap64':   {'ret': -1, 'fmt': 'mmap64(...)', 'args': []},
    'munmap':   {'ret': 0,  'fmt': 'munmap(0x%x, %d)', 'args': [('r0', 'x'), ('r1', 'd')]},
    'mprotect': {'ret': 0,  'fmt': 'mprotect(0x%x, %d, 0x%x)', 'args': [('r0', 'x'), ('r1', 'd'), ('r2', 'x')]},
    'brk':      {'ret': 0,  'fmt': 'brk(0x%x)', 'args': [('r0', 'x')]},
    
    # Device
    'ioctl':    {'ret': 0,  'fmt': 'ioctl(%d, 0x%lx, ...)', 'args': [('r0', 'd'), ('r1', 'lx')]},
    
    # Network
    'socket':   {'ret': -1, 'fmt': 'socket(%d, %d, %d)', 'args': [('r0', 'd'), ('r1', 'd'), ('r2', 'd')]},
    'connect':  {'ret': -1, 'fmt': 'connect(%d, ...)', 'args': [('r0', 'd')]},
    'bind':     {'ret': -1, 'fmt': 'bind(%d, ...)', 'args': [('r0', 'd')]},
    'listen':   {'ret': -1, 'fmt': 'listen(%d, %d)', 'args': [('r0', 'd'), ('r1', 'd')]},
    'accept':   {'ret': -1, 'fmt': 'accept(%d, ...)', 'args': [('r0', 'd')]},
    'send':     {'ret': -1, 'fmt': 'send(%d, 0x%x, %d)', 'args': [('r0', 'd'), ('r1', 'x'), ('r2', 'd')]},
    'recv':     {'ret': -1, 'fmt': 'recv(%d, 0x%x, %d)', 'args': [('r0', 'd'), ('r1', 'x'), ('r2', 'd')]},
    'setsockopt': {'ret': 0, 'fmt': 'setsockopt(%d, %d, %d)', 'args': [('r0', 'd'), ('r1', 'd'), ('r2', 'd')]},
    
    # Dynamic linking
    'dlopen':   {'ret': 0,  'fmt': 'dlopen("%s", %d)', 'args': [('r0', 's'), ('r1', 'd')]},
    'dlsym':    {'ret': 0,  'fmt': 'dlsym(0x%x, "%s")', 'args': [('r0', 'x'), ('r1', 's')]},
    'dlclose':  {'ret': 0,  'fmt': 'dlclose(0x%x)', 'args': [('r0', 'x')]},
    
    # Process
    'fork':     {'ret': 0,  'fmt': 'fork()', 'args': []},
    'vfork':    {'ret': 0,  'fmt': 'vfork()', 'args': []},
    'execve':   {'ret': -1, 'fmt': 'execve("%s", ...)', 'args': [('r0', 's')]},
    'system':   {'ret': -1, 'fmt': 'system("%s")', 'args': [('r0', 's')]},
    'popen':    {'ret': 0,  'fmt': 'popen("%s", "%s")', 'args': [('r0', 's'), ('r1', 's')]},
    'waitpid':  {'ret': -1, 'fmt': 'waitpid(%d, ...)', 'args': [('r0', 'd')]},
    
    # Threads
    'pthread_create':   {'ret': -1, 'fmt': 'pthread_create(...)', 'args': []},
    'pthread_join':     {'ret': 0,  'fmt': 'pthread_join(...)', 'args': []},
    'pthread_mutex_lock': {'ret': 0, 'fmt': 'pthread_mutex_lock(0x%x)', 'args': [('r0', 'x')]},
    
    # System
    'getenv':   {'ret': 0,  'fmt': 'getenv("%s")', 'args': [('r0', 's')]},
    'setenv':   {'ret': 0,  'fmt': 'setenv("%s", "%s")', 'args': [('r0', 's'), ('r1', 's')]},
    'uname':    {'ret': 0,  'fmt': 'uname(...)', 'args': []},
    'gethostname': {'ret': 0, 'fmt': 'gethostname(...)', 'args': []},
    'time':     {'ret': 0,  'fmt': 'time(...)', 'args': []},
    'gettimeofday': {'ret': 0, 'fmt': 'gettimeofday(...)', 'args': []},
    'sysinfo':  {'ret': 0,  'fmt': 'sysinfo(...)', 'args': []},
    
    # Signals
    'signal':   {'ret': 0,  'fmt': 'signal(%d, ...)', 'args': [('r0', 'd')]},
    'sigaction': {'ret': 0, 'fmt': 'sigaction(%d, ...)', 'args': [('r0', 'd')]},
    
    # Error handling
    '__errno_location': {'ret': 0, 'fmt': '__errno_location()', 'args': []},
    'perror':   {'ret': 0,  'fmt': 'perror("%s")', 'args': [('r0', 's')]},
    'exit':     {'ret': 0,  'fmt': 'exit(%d)', 'args': [('r0', 'd')]},
    'abort':    {'ret': 0,  'fmt': 'abort()', 'args': []},
}


# ============================================================================
# QEMU Runner
# ============================================================================

class QEMU:
    """Manages QEMU process"""
    
    def __init__(self, chroot: Path, binary: str, arch: str, port: int = 1234, args: list = None):
        self.chroot = Path(chroot).resolve()
        self.binary = binary
        self.arch = arch
        self.port = port
        self.args = args or []
        self.cfg = ARCHS[arch]
        self.proc: Optional[subprocess.Popen] = None
        self.last_error: str = ""
    
    def setup(self):
        """Ensure QEMU binary is in chroot"""
        qemu = self.cfg['qemu']
        src = Path(f"/usr/bin/{qemu}")
        dst = self.chroot / qemu
        
        if not dst.exists():
            if src.exists():
                log.info(f"Copying {qemu} to chroot...")
                subprocess.run(['sudo', 'cp', str(src), str(dst)], check=True)
            else:
                raise FileNotFoundError(f"QEMU not found: {src}")
    
    def preflight_check(self) -> tuple[bool, str]:
        """Run QEMU without GDB to check for immediate failures like missing libs"""
        self.setup()
        
        # Add common library paths via LD_LIBRARY_PATH
        ld_path = "/lib:/usr/lib:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu"
        
        cmd = ['sudo', 'chroot', str(self.chroot), 
               f"/{self.cfg['qemu']}", 
               '-E', f'LD_LIBRARY_PATH={ld_path}',
               self.binary]
        cmd.extend(self.args)
        
        log.debug(f"Preflight: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            combined = result.stdout + result.stderr
            
            # Check for library errors
            lib_match = re.search(r'error while loading shared libraries:\s*(\S+):', combined)
            if lib_match:
                return False, lib_match.group(1)
            
            # Check for other common errors
            if "No such file or directory" in combined:
                return False, combined
            
            return True, combined
            
        except subprocess.TimeoutExpired:
            # Program started and is running - that's good!
            return True, ""
        except Exception as e:
            return False, str(e)
    
    def start(self, env: dict = None) -> bool:
        """Start QEMU with GDB server"""
        self.setup()
        
        # Add common library paths
        ld_path = "/lib:/usr/lib:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu"
        
        cmd = ['sudo', 'chroot', str(self.chroot)]
        
        if env:
            for k, v in env.items():
                cmd.extend(['env', f'{k}={v}'])
        
        cmd.append(f"/{self.cfg['qemu']}")
        cmd.extend(['-E', f'LD_LIBRARY_PATH={ld_path}'])
        cmd.extend(['-g', str(self.port)])
        cmd.append(self.binary)
        cmd.extend(self.args)
        
        log.debug(f"CMD: {' '.join(cmd)}")
        
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(0.5)
            
            if self.proc.poll() is not None:
                _, stderr = self.proc.communicate()
                self.last_error = stderr
                log.error(f"QEMU died: {stderr[:500]}")
                return False
            
            self.last_error = ""
            log.ok(f"QEMU started on port {self.port}")
            return True
            
        except Exception as e:
            log.error(f"Start failed: {e}")
            self.last_error = str(e)
            return False
    
    def stop(self):
        """Stop QEMU"""
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except:
                self.proc.kill()
            self.proc = None
    
    @property
    def running(self) -> bool:
        return self.proc and self.proc.poll() is None


# ============================================================================
# Main Debugger Class
# ============================================================================

class IterDebugger:
    """Iterative debugger that builds GDB scripts"""
    
    def __init__(self, qemu: QEMU, outdir: str = "."):
        self.qemu = qemu
        self.outdir = Path(outdir)
        self.outdir.mkdir(parents=True, exist_ok=True)
        
        self.rules: list[Rule] = []
        self.hooks: list[Hook] = []
        self.iteration = 0
        self.history: list[Failure] = []
        self.symbols: dict = {}  # func_name -> address
        
        self.script_path = self.outdir / "debug.gdb"
        self.state_path = self.outdir / "state.json"
        
        self._gdb_proc: Optional[subprocess.Popen] = None
    
    # ---- State Management ----
    
    def load(self):
        """Load previous state"""
        if self.state_path.exists():
            try:
                with open(self.state_path) as f:
                    data = json.load(f)
                
                for r in data.get('rules', []):
                    self.rules.append(Rule(**r))
                
                for h in data.get('hooks', []):
                    self.hooks.append(Hook(**h))
                
                self.iteration = data.get('iteration', 0)
                self.symbols = data.get('symbols', {})
                
                log.info(f"Loaded {len(self.rules)} rules, {len(self.hooks)} hooks")
            except Exception as e:
                log.warn(f"Load failed: {e}")
    
    def save(self):
        """Save current state"""
        data = {
            'iteration': self.iteration,
            'rules': [
                {'addr': r.addr, 'action': r.action, 'ret_val': r.ret_val,
                 'skip_to': r.skip_to, 'reg_set': r.reg_set, 
                 'comment': r.comment, 'enabled': r.enabled}
                for r in self.rules
            ],
            'hooks': [
                {'addr': h.addr, 'name': h.name, 'fmt': h.fmt,
                 'args': h.args, 'enabled': h.enabled}
                for h in self.hooks
            ],
            'symbols': self.symbols,
        }
        with open(self.state_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    # ---- Binary Analysis ----
    
    def analyze_binary(self):
        """Analyze binary for symbols"""
        # Binary path should be relative to chroot (e.g., /usr/bin/foo)
        # NOT an absolute host path
        binary_rel = self.qemu.binary.lstrip('/')
        full_path = self.qemu.chroot / binary_rel
        
        if not full_path.exists():
            log.error(f"Binary not found: {full_path}")
            return
        
        log.info(f"Analyzing {full_path.name}...")
        
        # Get PLT entries (imported functions)
        try:
            result = subprocess.run(
                ['objdump', '-d', '-j', '.plt', str(full_path)],
                capture_output=True, text=True, timeout=30
            )
            
            # Parse PLT entries - look for function@plt patterns
            for match in re.finditer(r'([0-9a-f]+)\s+<(\w+)@plt>:', result.stdout):
                addr_str = match.group(1)
                func_name = match.group(2)
                self.symbols[func_name] = int(addr_str, 16)
            
            log.ok(f"Found {len(self.symbols)} PLT symbols")
            
        except Exception as e:
            log.warn(f"PLT analysis failed: {e}")
        
        # Also try dynamic symbols
        try:
            result = subprocess.run(
                ['nm', '-D', str(full_path)],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        addr = int(parts[0], 16)
                        name = parts[2]
                        if name not in self.symbols:
                            self.symbols[name] = addr
                    except ValueError:
                        pass
            
        except Exception as e:
            log.debug(f"nm failed: {e}")
    
    def auto_add_hooks(self):
        """Add hooks for known functions found in binary"""
        added = 0
        arch = self.qemu.cfg
        
        for func_name, addr in self.symbols.items():
            if func_name in FUNCS and addr > 0:
                # Check if hook already exists
                existing = [h for h in self.hooks if h.addr == addr]
                if existing:
                    continue
                
                func_info = FUNCS[func_name]
                
                # Adjust argument registers for architecture
                args = []
                for i, (_, atype) in enumerate(func_info.get('args', [])):
                    if i < len(arch['args']):
                        args.append((arch['args'][i], atype))
                
                hook = Hook(
                    addr=addr,
                    name=func_name,
                    fmt=func_info['fmt'],
                    args=args
                )
                self.hooks.append(hook)
                added += 1
        
        if added:
            log.ok(f"Added {added} function hooks")
    
    # ---- GDB Script Generation ----
    
    def gen_script(self) -> str:
        """Generate GDB script"""
        arch = self.qemu.cfg
        
        lines = [
            "# Auto-generated GDB script",
            f"# Iteration: {self.iteration}",
            f"# Time: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "set pagination off",
            "set confirm off",
            "set print pretty on",
            "",
            f"target remote localhost:{self.qemu.port}",
            "",
        ]
        
        # Add hooks
        if self.hooks:
            lines.append("# === HOOKS ===")
            for h in self.hooks:
                lines.extend(h.to_gdb())
                lines.append("")
        
        # Add rules
        if self.rules:
            lines.append("# === RULES ===")
            for r in self.rules:
                lines.extend(r.to_gdb(arch))
                lines.append("")
        
        # Signal handlers
        lines.extend([
            "# === SIGNALS ===",
            "handle SIGSEGV stop print",
            "handle SIGABRT stop print",
            "handle SIGILL stop print",
            "handle SIGBUS stop print",
            "",
            "# Go!",
            "continue",
        ])
        
        content = '\n'.join(lines)
        with open(self.script_path, 'w') as f:
            f.write(content)
        
        return content
    
    # ---- Execution ----
    
    def run(self, timeout: float = 60.0) -> tuple[bool, str, Failure]:
        """Run with GDB and current script"""
        self.iteration += 1
        log.header(f"Iteration {self.iteration}")
        
        self.gen_script()
        
        if not self.qemu.start():
            # Check if QEMU captured a library error
            if self.qemu.last_error:
                log.debug(f"QEMU error: {self.qemu.last_error}")
                lib_match = re.search(r'error while loading shared libraries:\s*(\S+):', self.qemu.last_error)
                if lib_match:
                    fail = Failure(FailType.LIB_MISSING)
                    fail.info['missing_lib'] = lib_match.group(1)
                    return False, self.qemu.last_error, fail
            return False, "QEMU start failed", Failure(FailType.UNKNOWN)
        
        time.sleep(0.5)
        
        gdb_cmd = [
            self.qemu.cfg['gdb'],
            '-batch',
            '-x', str(self.script_path),
        ]
        
        log.debug(f"GDB command: {' '.join(gdb_cmd)}")
        
        try:
            self._gdb_proc = subprocess.Popen(
                gdb_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            output_lines = []
            start = time.time()
            
            # Also capture QEMU stderr in background
            qemu_stderr_lines = []
            def read_qemu_stderr():
                if self.qemu.proc and self.qemu.proc.stderr:
                    try:
                        for line in iter(self.qemu.proc.stderr.readline, ''):
                            if line:
                                qemu_stderr_lines.append(line.rstrip())
                                log.debug(f"QEMU stderr: {line.rstrip()}")
                    except:
                        pass
            
            stderr_thread = threading.Thread(target=read_qemu_stderr, daemon=True)
            stderr_thread.start()
            
            while time.time() - start < timeout:
                if self._gdb_proc.poll() is not None:
                    break
                
                try:
                    rlist, _, _ = select.select([self._gdb_proc.stdout], [], [], 0.5)
                    if rlist:
                        line = self._gdb_proc.stdout.readline()
                        if line:
                            line = line.rstrip()
                            output_lines.append(line)
                            
                            # Show hooks in real-time
                            if '[H]' in line:
                                log.hook("", line.split('[H]')[1].strip())
                            elif Logger.VERBOSE:
                                print(f"{C.DIM}{line}{C.E}")
                except:
                    pass
            
            # Handle timeout or completion
            if self._gdb_proc.poll() is None:
                log.warn("Timeout - terminating")
                self._gdb_proc.terminate()
                try:
                    remaining, _ = self._gdb_proc.communicate(timeout=2)
                    output_lines.extend(remaining.split('\n'))
                except:
                    self._gdb_proc.kill()
            else:
                remaining = self._gdb_proc.stdout.read()
                output_lines.extend(remaining.split('\n'))
            
            # Wait a bit for stderr thread
            stderr_thread.join(timeout=1)
            
            output = '\n'.join(output_lines)
            qemu_output = '\n'.join(qemu_stderr_lines)
            combined_output = output + '\n' + qemu_output
            
            # Check for success - must be exit code 0, not 127 (library error)
            if "exited normally" in output:
                log.ok("Program exited normally!")
                return True, output, Failure(FailType.UNKNOWN)
            
            # Exit code 127 (0177 octal) = shared library not found OR symbol lookup error
            if "exited with code 0177" in output or "exited with code 127" in output:
                # Check for undefined symbol error first
                symbol_match = re.search(r'undefined symbol:\s*(\S+)', combined_output)
                if symbol_match:
                    log.error("Program failed - undefined symbol!")
                    fail = Failure(FailType.SYMBOL_MISSING)
                    fail.info['exit_code'] = 127
                    fail.info['missing_symbol'] = symbol_match.group(1)
                    
                    # Try to figure out which library should have it
                    lib_match = re.search(r'symbol lookup error:\s*(\S+):', combined_output)
                    if lib_match:
                        fail.info['in_binary'] = lib_match.group(1)
                    
                    return False, combined_output, fail
                
                log.error("Program failed to load - missing shared library!")
                fail = Failure(FailType.LIB_MISSING)
                fail.info['exit_code'] = 127
                
                # Try to extract library name from QEMU stderr first, then GDB output
                lib_match = re.search(r'error while loading shared libraries:\s*(\S+):', combined_output)
                if lib_match:
                    fail.info['missing_lib'] = lib_match.group(1)
                    log.info(f"Missing library identified: {lib_match.group(1)}")
                else:
                    # Show what we captured for debugging
                    if qemu_stderr_lines:
                        log.debug(f"QEMU stderr captured: {qemu_stderr_lines}")
                    
                    # Try running preflight again to get the actual error
                    log.info("Running diagnostic to identify missing library...")
                    ok, diag_result = self.qemu.preflight_check()
                    if not ok and diag_result and '.so' in diag_result:
                        fail.info['missing_lib'] = diag_result
                        log.info(f"Missing library identified: {diag_result}")
                
                return False, combined_output, fail
            
            # Other non-zero exit codes
            exit_match = re.search(r'exited with code (\d+)', output)
            if exit_match:
                code = int(exit_match.group(1))
                if code == 0:
                    log.ok("Program exited with code 0")
                    return True, output, Failure(FailType.UNKNOWN)
                else:
                    log.warn(f"Program exited with code {code}")
                    fail = Failure(FailType.UNKNOWN)
                    fail.info['exit_code'] = code
                    return False, output, fail
            
            # Parse failure
            failure = self._parse_output(output)
            self.history.append(failure)
            
            return False, output, failure
            
        except Exception as e:
            log.error(f"GDB failed: {e}")
            return False, str(e), Failure(FailType.UNKNOWN)
        finally:
            self.qemu.stop()
            self._gdb_proc = None
    
    def _parse_output(self, output: str) -> Failure:
        """Parse GDB output to identify failure"""
        fail = Failure(FailType.UNKNOWN)
        
        # Signal detection
        sig_map = [
            (r'SIGSEGV', FailType.SIGSEGV),
            (r'SIGABRT', FailType.SIGABRT),
            (r'SIGILL', FailType.SIGILL),
            (r'SIGBUS', FailType.SIGBUS),
            (r'SIGFPE', FailType.SIGFPE),
        ]
        
        for pattern, ftype in sig_map:
            if re.search(pattern, output):
                fail.type = ftype
                break
        
        # Parse backtrace first - this is the authoritative source
        # Format: #0  0x00012345 in function_name () at file.c:123
        #    or:  #0  0x00012345 in function_name ()
        #    or:  #0  0x00012345 in ?? ()
        bt_pattern = r'#(\d+)\s+(?:0x)?([0-9a-fA-F]+)\s+in\s+(\S+)\s*\([^)]*\)(?:\s+at\s+(\S+))?'
        bt_matches = re.findall(bt_pattern, output)
        
        fail.bt = []
        for match in bt_matches[:10]:
            frame_num, addr, func, source = match
            addr_int = int(addr, 16)
            # Clean up function name (remove trailing garbage)
            func = func.split('@')[0] if '@' in func else func
            
            bt_entry = {
                'frame': int(frame_num),
                'addr': addr_int,
                'func': func if func != '??' else '',
                'source': source if source else ''
            }
            fail.bt.append(bt_entry)
        
        # For signals, the fault location is typically frame #0
        # But we want the FIRST frame that's in user code (not libc, not ld-linux)
        if fail.bt:
            # Default to frame 0
            fail.addr = fail.bt[0]['addr']
            fail.func = fail.bt[0]['func']
            
            # Try to find the first "interesting" frame (not in system libs)
            system_prefixes = ('__', '_dl_', '_start', 'ld-linux', '__libc_', '_GI_')
            for entry in fail.bt:
                func = entry['func']
                if func and not any(func.startswith(p) for p in system_prefixes):
                    fail.addr = entry['addr']
                    fail.func = func
                    fail.info['fault_frame'] = entry['frame']
                    break
        
        # Also check for "Program received signal" line which may have fault address
        # Format: Program received signal SIGSEGV, Segmentation fault.
        #         0x00012345 in function ()
        sig_addr_match = re.search(
            r'Program received signal \w+.*?\n\s*(?:0x)?([0-9a-fA-F]+)\s+in\s+(\S+)',
            output, re.MULTILINE
        )
        if sig_addr_match:
            # This is the actual fault location, prefer it
            fail.addr = int(sig_addr_match.group(1), 16)
            fail.func = sig_addr_match.group(2).split('(')[0].split('@')[0]
        
        # If we still don't have an address, try other patterns
        if fail.addr == 0:
            # Try: stopped at 0x12345
            stop_match = re.search(r'stopped.*?(?:0x)?([0-9a-fA-F]{6,})', output, re.IGNORECASE)
            if stop_match:
                fail.addr = int(stop_match.group(1), 16)
            
            # Try: $pc = 0x12345
            pc_match = re.search(r'\$pc\s*=\s*(?:0x)?([0-9a-fA-F]+)', output)
            if pc_match:
                fail.addr = int(pc_match.group(1), 16)
        
        # File issues from hooks
        file_match = re.search(r'\[H\]\s*(?:open|fopen|access|stat)\("([^"]+)"', output)
        if file_match:
            fail.info['last_file'] = file_match.group(1)
        
        return fail
    
    # ---- Interactive Menu ----
    
    def prompt(self, fail: Failure, output: str) -> Optional[Rule]:
        """Interactive prompt for user action"""
        arch = self.qemu.cfg
        
        print()
        log.header("FAILURE DETECTED")
        print(f"  {C.R}Type:{C.E}    {fail.type.name}")
        print(f"  {C.R}Address:{C.E} 0x{fail.addr:08x}")
        print(f"  {C.R}Function:{C.E} {fail.func or 'unknown'}")
        
        # Special handling for undefined symbol errors
        if fail.type == FailType.SYMBOL_MISSING:
            missing_symbol = fail.info.get('missing_symbol', 'unknown')
            in_binary = fail.info.get('in_binary', 'unknown')
            
            # Demangle C++ symbol if possible
            demangled = missing_symbol
            try:
                result = subprocess.run(['c++filt', missing_symbol], 
                                       capture_output=True, text=True, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    demangled = result.stdout.strip()
            except:
                pass
            
            print(f"\n  {C.R}Missing Symbol:{C.E} {missing_symbol}")
            if demangled != missing_symbol:
                print(f"  {C.C}Demangled:{C.E} {demangled}")
            print(f"  {C.C}Required by:{C.E} {in_binary}")
            
            print(f"\n{C.Y}This is an undefined symbol error - a stub library exists but lacks this function.{C.E}")
            print(f"\n{C.C}Options:{C.E}")
            print(f"  1. Create stub with dummy symbol (function returns 0/NULL)")
            print(f"  2. Search for the real library containing this symbol")
            print(f"  3. Show tips")
            print(f"  9. Save & quit")
            print(f"  0. Quit")
            
            while True:
                choice = input(f"\n{C.G}Choice: {C.E}").strip()
                
                if choice == '1':
                    # Figure out which library needs this symbol
                    lib_name = None
                    if 'IPC' in missing_symbol or 'ipc' in in_binary.lower():
                        lib_name = 'libipc.so'
                    elif 'procstat' in in_binary.lower():
                        lib_name = 'libprocstat.so'
                    else:
                        lib_name = input(f"Which library should contain this symbol? ").strip()
                    
                    if lib_name:
                        if self.create_stub_library_with_symbol(lib_name, missing_symbol):
                            return None  # Retry
                
                elif choice == '2':
                    # Search for the symbol in existing libraries
                    log.info(f"Searching for symbol in chroot libraries...")
                    found = self.search_symbol_in_libs(missing_symbol)
                    if found:
                        for lib_path in found:
                            print(f"    {C.G}Found in:{C.E} {lib_path}")
                    else:
                        log.warn("Symbol not found in any library in chroot")
                
                elif choice == '3':
                    print(f"\n{C.C}Tips:{C.E}")
                    print(f"  • The stub library we created is empty - it has no actual functions")
                    print(f"  • You need the REAL library from the device/firmware")
                    print(f"  • Check other firmware partitions or SDK for the actual .so file")
                    print(f"  • For testing, we can create a stub that returns 0/NULL")
                    print(f"  • Symbol '{demangled}' suggests this is C++ code")
                
                elif choice == '9':
                    self.save()
                    sys.exit(0)
                elif choice == '0':
                    sys.exit(0)
        
        # Special handling for library issues
        if fail.type == FailType.LIB_MISSING:
            missing_lib = fail.info.get('missing_lib', 'unknown')
            print(f"\n  {C.R}Missing Library:{C.E} {missing_lib}")
            print(f"\n{C.Y}This is a dynamic linker failure - the library must be resolved before the program can run.{C.E}")
            print(f"\n{C.C}Options:{C.E}")
            print(f"  1. Search for library in chroot")
            print(f"  2. Create stub library (requires cross-compiler)")
            print(f"  3. Create ALL missing stub libraries at once")
            print(f"  4. Show search tips")
            print(f"  9. Save & quit")
            print(f"  0. Quit")
            
            while True:
                choice = input(f"\n{C.G}Choice: {C.E}").strip()
                
                if choice == '1':
                    found = self.find_library_in_chroot(missing_lib)
                    if found:
                        log.ok(f"Found: {found}")
                        link_choice = input(f"Symlink to /usr/lib? [Y/n]: ").strip().lower()
                        if link_choice in ('', 'y', 'yes'):
                            target = self.qemu.chroot / 'usr' / 'lib' / missing_lib
                            try:
                                subprocess.run(['sudo', 'ln', '-sf', str(found), str(target)], check=True)
                                log.ok(f"Created symlink: {target} -> {found}")
                                return None  # Retry without new rule
                            except Exception as e:
                                log.error(f"Failed: {e}")
                    else:
                        log.warn(f"Not found in chroot")
                        # Also search for similar names
                        base_name = missing_lib.split('.')[0]
                        result = subprocess.run(
                            ['find', str(self.qemu.chroot), '-name', f'{base_name}*', '-type', 'f'],
                            capture_output=True, text=True
                        )
                        if result.stdout.strip():
                            print(f"\n{C.C}Similar files found:{C.E}")
                            for line in result.stdout.strip().split('\n')[:10]:
                                print(f"    {line}")
                
                elif choice == '2':
                    if missing_lib and missing_lib != 'unknown':
                        if self.create_stub_library(missing_lib):
                            return None  # Retry
                    else:
                        log.error("Cannot create stub - library name unknown")
                        log.info("Try option 3 to scan binary and create all missing stubs")
                
                elif choice == '3':
                    created = self.create_all_stub_libraries()
                    if created > 0:
                        return None  # Retry
                
                elif choice == '4':
                    print(f"\n{C.C}Tips for finding {missing_lib}:{C.E}")
                    print(f"  • Check other firmware versions for this device")
                    print(f"  • Search SDK/toolchain directories")
                    print(f"  • Try: apt-file search {missing_lib}")
                    print(f"  • For vendor libs, check if it's in another squashfs partition")
                    print(f"  • Use 'binwalk -e' on the full firmware image")
                
                elif choice == '9':
                    self.save()
                    sys.exit(0)
                elif choice == '0':
                    sys.exit(0)
        
        if fail.bt:
            print(f"\n  {C.C}Backtrace:{C.E}")
            for entry in fail.bt[:8]:
                if isinstance(entry, dict):
                    frame = entry.get('frame', '?')
                    addr = entry.get('addr', 0)
                    func = entry.get('func', '??')
                    source = entry.get('source', '')
                    
                    # Highlight the frame we identified as the culprit
                    marker = f"{C.R}→{C.E}" if addr == fail.addr else " "
                    source_str = f" at {source}" if source else ""
                    print(f"   {marker} #{frame}  0x{addr:08x} in {func or '??'}(){source_str}")
                else:
                    # Legacy string format
                    print(f"    {entry}")
        
        if fail.info:
            print(f"\n  {C.C}Context:{C.E}")
            for k, v in fail.info.items():
                print(f"    {k}: {v}")
        
        # Suggest showing output for non-signal failures
        if fail.type == FailType.UNKNOWN and fail.info.get('exit_code'):
            print(f"\n  {C.Y}Tip:{C.E} Program exited with error. Try option 5 to see full output,")
            print(f"       or re-run with arguments: --args -n -h  (to see program's help)")
        
        print(f"\n{C.Y}Actions:{C.E}")
        print("  1. Skip call (jump past it)")
        print("  2. Force return value")
        print("  3. Set registers")
        print("  4. Show disassembly")
        print("  5. Show full output")
        print("  6. Edit existing rules")
        print("  7. Auto-suggest fix")
        print("  8. Continue without change")
        if fail.bt and len(fail.bt) > 1:
            print("  b. Select different backtrace frame")
        print("  9. Save & quit")
        print("  0. Quit (no save)")
        
        while True:
            try:
                choice = input(f"\n{C.G}Choice [0-9]: {C.E}").strip()
                
                if choice == '1':
                    return self._make_skip_rule(fail, arch)
                elif choice == '2':
                    return self._make_return_rule(fail, arch)
                elif choice == '3':
                    return self._make_reg_rule(fail, arch)
                elif choice == '4':
                    self._show_disasm(fail)
                elif choice == '5':
                    print(f"\n{C.DIM}{output}{C.E}")
                elif choice == '6':
                    self._edit_rules()
                elif choice == '7':
                    return self._auto_suggest(fail)
                elif choice == '8':
                    return None
                elif choice.lower() == 'b' and fail.bt and len(fail.bt) > 1:
                    print(f"\n{C.C}Select frame to patch:{C.E}")
                    for entry in fail.bt:
                        if isinstance(entry, dict):
                            frame = entry.get('frame', '?')
                            addr = entry.get('addr', 0)
                            func = entry.get('func', '??')
                            print(f"    #{frame}  0x{addr:08x}  {func or '??'}")
                    
                    frame_choice = input(f"\n{C.G}Frame number: {C.E}").strip()
                    try:
                        frame_num = int(frame_choice)
                        for entry in fail.bt:
                            if isinstance(entry, dict) and entry.get('frame') == frame_num:
                                fail.addr = entry['addr']
                                fail.func = entry.get('func', '')
                                log.ok(f"Now targeting frame #{frame_num} at 0x{fail.addr:08x}")
                                break
                    except ValueError:
                        pass
                elif choice == '9':
                    self.save()
                    log.ok("Saved. Goodbye!")
                    sys.exit(0)
                elif choice == '0':
                    sys.exit(0)
                    
            except (KeyboardInterrupt, EOFError):
                print("\nInterrupted")
                self.save()
                sys.exit(1)
    
    def _make_skip_rule(self, fail: Failure, arch: dict) -> Rule:
        """Create skip rule"""
        default_to = fail.addr + arch['insn_size']
        
        to_str = input(f"Skip to [0x{default_to:08x}]: ").strip()
        skip_to = int(to_str, 16) if to_str else default_to
        
        comment = input("Comment: ").strip() or f"Skip at {fail.func or hex(fail.addr)}"
        
        return Rule(
            addr=fail.addr,
            action='skip',
            skip_to=skip_to,
            comment=comment
        )
    
    def _make_return_rule(self, fail: Failure, arch: dict) -> Rule:
        """Create return rule"""
        # Suggest based on known functions
        suggested = 0
        if fail.func in FUNCS:
            suggested = FUNCS[fail.func]['ret']
        
        ret_str = input(f"Return value [{suggested}]: ").strip()
        ret_val = int(ret_str, 0) if ret_str else suggested
        
        comment = input("Comment: ").strip() or f"Force {fail.func or 'func'}() -> {ret_val}"
        
        return Rule(
            addr=fail.addr,
            action='ret',
            ret_val=ret_val,
            comment=comment
        )
    
    def _make_reg_rule(self, fail: Failure, arch: dict) -> Rule:
        """Create register-setting rule"""
        print(f"Registers: {', '.join(arch['args'][:4])}, {arch['ret']}, {arch['pc']}")
        
        reg_set = {}
        while True:
            pair = input("  reg=val (empty to finish): ").strip()
            if not pair:
                break
            if '=' in pair:
                reg, val = pair.split('=', 1)
                reg_set[reg.strip()] = int(val.strip(), 0)
        
        comment = input("Comment: ").strip()
        
        return Rule(
            addr=fail.addr,
            action='set',
            reg_set=reg_set,
            comment=comment
        )
    
    def _auto_suggest(self, fail: Failure) -> Optional[Rule]:
        """Auto-suggest a fix based on failure context"""
        arch = self.qemu.cfg
        
        # Check if it's a known function
        if fail.func in FUNCS:
            func_info = FUNCS[fail.func]
            suggested_ret = func_info['ret']
            
            print(f"\n{C.G}Suggestion:{C.E} Force {fail.func}() to return {suggested_ret}")
            confirm = input("Apply? [Y/n]: ").strip().lower()
            
            if confirm in ('', 'y', 'yes'):
                return Rule(
                    addr=fail.addr,
                    action='ret',
                    ret_val=suggested_ret,
                    comment=f"Auto: {fail.func}() -> {suggested_ret}"
                )
        
        # Generic suggestion: skip the instruction
        print(f"\n{C.Y}No specific suggestion. Options:{C.E}")
        print("  1. Skip this instruction")
        print("  2. Return 0")
        print("  3. Return -1")
        print("  4. Cancel")
        
        choice = input("Choice [1-4]: ").strip()
        
        if choice == '1':
            return Rule(
                addr=fail.addr,
                action='skip',
                skip_to=fail.addr + arch['insn_size'],
                comment=f"Auto: skip at 0x{fail.addr:08x}"
            )
        elif choice == '2':
            return Rule(addr=fail.addr, action='ret', ret_val=0, comment="Auto: return 0")
        elif choice == '3':
            return Rule(addr=fail.addr, action='ret', ret_val=-1, comment="Auto: return -1")
        
        return None
    
    def _show_disasm(self, fail: Failure):
        """Show disassembly around failure"""
        if not self.qemu.start():
            log.error("Could not start QEMU for disassembly")
            return
        
        time.sleep(0.5)
        
        script = f"""target remote localhost:{self.qemu.port}
disassemble 0x{fail.addr:08x}-32, 0x{fail.addr:08x}+32
quit
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
            f.write(script)
            tmp = f.name
        
        try:
            result = subprocess.run(
                [self.qemu.cfg['gdb'], '-batch', '-x', tmp],
                capture_output=True, text=True, timeout=10
            )
            print(f"\n{C.C}Disassembly:{C.E}")
            print(result.stdout)
        except Exception as e:
            log.error(f"Disassembly failed: {e}")
        finally:
            os.unlink(tmp)
            self.qemu.stop()
    
    def _edit_rules(self):
        """Edit existing rules"""
        if not self.rules:
            print("No rules yet.")
            return
        
        print(f"\n{C.C}Rules:{C.E}")
        for i, r in enumerate(self.rules):
            status = "" if r.enabled else f"{C.DIM}[disabled]{C.E} "
            print(f"  {i+1}. {status}0x{r.addr:08x} [{r.action}] {r.comment}")
        
        action = input("\nEnter number to toggle/delete, or 'c' to cancel: ").strip()
        if action.lower() == 'c':
            return
        
        try:
            idx = int(action) - 1
            if 0 <= idx < len(self.rules):
                sub = input("  [t]oggle, [d]elete? ").strip().lower()
                if sub == 'd':
                    removed = self.rules.pop(idx)
                    log.info(f"Deleted rule at 0x{removed.addr:08x}")
                elif sub == 't':
                    self.rules[idx].enabled = not self.rules[idx].enabled
                    state = "enabled" if self.rules[idx].enabled else "disabled"
                    log.info(f"Rule {state}")
        except ValueError:
            pass
    
    # ---- Main Loop ----
    
    def check_libraries(self, binary_path: str = None, checked: set = None) -> list[str]:
        """Check for missing libraries, including transitive dependencies"""
        if checked is None:
            checked = set()
        
        if binary_path is None:
            binary_rel = self.qemu.binary.lstrip('/')
            full_path = self.qemu.chroot / binary_rel
        else:
            full_path = Path(binary_path)
        
        if not full_path.exists():
            return []
        
        # Avoid infinite loops
        if str(full_path) in checked:
            return []
        checked.add(str(full_path))
        
        missing = []
        all_needed = []
        
        # Common library search paths
        lib_paths = [
            'lib', 'usr/lib', 'lib/aarch64-linux-gnu', 'usr/lib/aarch64-linux-gnu',
            'lib64', 'usr/lib64', 'lib/arm-linux-gnueabihf', 'usr/lib/arm-linux-gnueabihf'
        ]
        
        try:
            # Use readelf to find needed libraries
            result = subprocess.run(
                ['readelf', '-d', str(full_path)],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.split('\n'):
                if 'NEEDED' in line:
                    match = re.search(r'\[(.+?)\]', line)
                    if match:
                        all_needed.append(match.group(1))
            
            for lib in all_needed:
                found_path = None
                for lp in lib_paths:
                    lib_full = self.qemu.chroot / lp / lib
                    if lib_full.exists():
                        found_path = lib_full
                        break
                    # Also check for symlinks like libfoo.so -> libfoo.so.1
                    lib_dir = self.qemu.chroot / lp
                    if lib_dir.exists():
                        for candidate in lib_dir.glob(f"{lib}*"):
                            if candidate.exists():
                                found_path = candidate
                                break
                    if found_path:
                        break
                
                if not found_path:
                    if lib not in missing:
                        missing.append(lib)
                else:
                    # Recursively check this library's dependencies
                    transitive = self.check_libraries(str(found_path), checked)
                    for t in transitive:
                        if t not in missing:
                            missing.append(t)
                    
        except Exception as e:
            log.debug(f"Library check failed for {full_path}: {e}")
        
        return missing
    
    def check_libraries_via_qemu(self) -> list[str]:
        """Use QEMU with LD_TRACE to find all missing libraries (like ldd)"""
        self.qemu.setup()
        
        cmd = [
            'sudo', 'chroot', str(self.qemu.chroot),
            f"/{self.qemu.cfg['qemu']}",
            '-E', 'LD_TRACE_LOADED_OBJECTS=1',
            '-E', 'LD_WARN=1',
            '-E', 'LD_LIBRARY_PATH=/lib:/usr/lib',
            self.qemu.binary
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
            
            missing = []
            # Parse ldd-style output: "libfoo.so => not found"
            for line in output.split('\n'):
                if 'not found' in line.lower():
                    match = re.match(r'\s*(\S+)\s+=>\s+not found', line)
                    if match:
                        lib = match.group(1)
                        if lib not in missing:
                            missing.append(lib)
                
                # Also catch "error while loading" messages
                lib_match = re.search(r'error while loading shared libraries:\s*(\S+):', line)
                if lib_match:
                    lib = lib_match.group(1)
                    if lib not in missing:
                        missing.append(lib)
            
            return missing
            
        except Exception as e:
            log.debug(f"QEMU library trace failed: {e}")
            # Fall back to static analysis
            return self.check_libraries()
    
    def check_all_libraries_deep(self) -> list[str]:
        """Deep check using multiple methods"""
        # Try QEMU-based check first (most accurate)
        missing = self.check_libraries_via_qemu()
        
        # Also do static analysis to catch anything else
        static_missing = self.check_libraries()
        for lib in static_missing:
            if lib not in missing:
                missing.append(lib)
        
        return missing
    
    def create_all_stub_libraries(self) -> int:
        """Create stubs for all missing libraries at once (including transitive deps)"""
        log.info("Scanning for all missing libraries...")
        
        # First try QEMU-based check
        log.info("  Running QEMU library trace (like ldd)...")
        qemu_missing = self.check_libraries_via_qemu()
        if qemu_missing:
            log.info(f"  QEMU trace found {len(qemu_missing)} missing: {qemu_missing}")
        
        # Then static analysis
        log.info("  Running static analysis on binary...")
        static_missing = self.check_libraries()
        if static_missing:
            log.info(f"  Static analysis found {len(static_missing)} missing: {static_missing}")
        
        # Combine
        missing = list(qemu_missing)
        for lib in static_missing:
            if lib not in missing:
                missing.append(lib)
        
        if not missing:
            log.ok("No missing libraries detected")
            log.info("The library might be a transitive dependency.")
            log.info("Try running with -v for verbose output to see what's happening.")
            return 0
        
        log.info(f"Found {len(missing)} total missing libraries:")
        for lib in missing:
            print(f"    {C.Y}•{C.E} {lib}")
        
        confirm = input(f"\n{C.G}Create stubs for all? [Y/n]: {C.E}").strip().lower()
        if confirm not in ('', 'y', 'yes'):
            return 0
        
        created = 0
        for lib in missing:
            if self.create_stub_library(lib):
                created += 1
        
        log.ok(f"Created {created}/{len(missing)} stub libraries")
        return created
    
    def create_stub_library_with_symbol(self, lib_name: str, symbol: str) -> bool:
        """Create a stub library that exports a specific symbol"""
        if not lib_name:
            log.error("No library name specified")
            return False
        
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / 'stub.c'
            
            # Generate C code that exports the symbol
            # Handle both C and C++ symbols
            if symbol.startswith('_Z'):
                # C++ mangled symbol - create as extern "C" 
                code = f'''
// Stub library with symbol: {symbol}
#ifdef __cplusplus
extern "C" {{
#endif

// Stub function that returns 0/NULL
void* {symbol}(void) {{
    return (void*)0;
}}

#ifdef __cplusplus
}}
#endif
'''
            else:
                # C symbol
                code = f'''
// Stub library with symbol: {symbol}
void* {symbol}(void) {{
    return (void*)0;
}}
'''
            
            src.write_text(code)
            out = Path(tmpdir) / lib_name
            
            compilers = {
                'arm': 'arm-linux-gnueabihf-gcc',
                'arm64': 'aarch64-linux-gnu-gcc',
                'mips': 'mips-linux-gnu-gcc',
                'mipsel': 'mipsel-linux-gnu-gcc',
                'ppc': 'powerpc-linux-gnu-gcc',
            }
            
            cc = compilers.get(self.qemu.arch, 'gcc')
            
            try:
                soname = lib_name.split('.so')[0] + '.so'
                subprocess.run(
                    [cc, '-shared', '-fPIC', f'-Wl,-soname,{soname}', 
                     '-o', str(out), str(src)],
                    check=True, capture_output=True
                )
                
                # Install to lib paths
                lib_paths = ['lib', 'usr/lib']
                for lp in lib_paths:
                    lib_dir = self.qemu.chroot / lp
                    if lib_dir.exists():
                        stub_path = lib_dir / lib_name
                        subprocess.run(['sudo', 'cp', str(out), str(stub_path)], check=True)
                        log.ok(f"Created stub with symbol: {stub_path}")
                        
                        # Verify the symbol is there
                        result = subprocess.run(['nm', '-D', str(stub_path)], 
                                              capture_output=True, text=True)
                        if symbol in result.stdout:
                            log.ok(f"Verified symbol {symbol} is exported")
                        return True
                
            except subprocess.CalledProcessError as e:
                log.warn(f"Compilation failed: {e.stderr.decode() if e.stderr else e}")
            except Exception as e:
                log.warn(f"Could not create stub: {e}")
        
        return False
    
    def search_symbol_in_libs(self, symbol: str) -> list[str]:
        """Search for a symbol in all libraries in the chroot"""
        found = []
        lib_paths = ['lib', 'usr/lib', 'lib64', 'usr/lib64']
        
        for lp in lib_paths:
            lib_dir = self.qemu.chroot / lp
            if not lib_dir.exists():
                continue
            
            for lib_file in lib_dir.glob('*.so*'):
                if not lib_file.is_file():
                    continue
                try:
                    result = subprocess.run(
                        ['nm', '-D', str(lib_file)],
                        capture_output=True, text=True, timeout=5
                    )
                    if symbol in result.stdout:
                        found.append(str(lib_file))
                except:
                    pass
        
        return found
    
    def find_library_in_chroot(self, lib_name: str) -> Optional[Path]:
        """Search for a library anywhere in the chroot"""
        try:
            result = subprocess.run(
                ['find', str(self.qemu.chroot), '-name', f'{lib_name}*', '-type', 'f'],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split('\n'):
                if line:
                    return Path(line)
        except:
            pass
        return None
    
    def create_stub_library(self, lib_name: str) -> bool:
        """Create a minimal stub .so that does nothing"""
        if not lib_name or lib_name == 'unknown':
            log.error("Cannot create stub for unknown library name")
            return False
        
        # Create minimal ELF stub using a C file
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / 'stub.c'
            src.write_text('// Empty stub library\nvoid __stub_init(void) {}\n')
            
            out = Path(tmpdir) / lib_name
            
            # Determine compiler based on arch
            compilers = {
                'arm': 'arm-linux-gnueabihf-gcc',
                'arm64': 'aarch64-linux-gnu-gcc',
                'mips': 'mips-linux-gnu-gcc',
                'mipsel': 'mipsel-linux-gnu-gcc',
                'ppc': 'powerpc-linux-gnu-gcc',
            }
            
            cc = compilers.get(self.qemu.arch, 'gcc')
            
            try:
                # Create the stub with proper soname
                soname = lib_name.split('.so')[0] + '.so'
                subprocess.run(
                    [cc, '-shared', '-fPIC', '-nostdlib', f'-Wl,-soname,{soname}', 
                     '-o', str(out), str(src)],
                    check=True, capture_output=True
                )
                
                # Install to multiple common library paths
                lib_paths = [
                    'lib',
                    'usr/lib', 
                    'lib/aarch64-linux-gnu',
                    'usr/lib/aarch64-linux-gnu',
                    'lib64',
                ]
                
                installed = []
                for lp in lib_paths:
                    lib_dir = self.qemu.chroot / lp
                    if lib_dir.exists() or lp in ('lib', 'usr/lib'):
                        lib_dir.mkdir(parents=True, exist_ok=True)
                        stub_path = lib_dir / lib_name
                        subprocess.run(['sudo', 'cp', str(out), str(stub_path)], check=True)
                        installed.append(str(stub_path))
                
                if installed:
                    log.ok(f"Created stub in: {installed[0]}")
                    if len(installed) > 1:
                        log.debug(f"Also copied to {len(installed)-1} other paths")
                    return True
                else:
                    log.error("No library paths found")
                    return False
                    
            except subprocess.CalledProcessError as e:
                log.warn(f"Compilation failed: {e.stderr.decode() if e.stderr else e}")
                return False
            except FileNotFoundError:
                log.warn(f"Cross-compiler not found: {cc}")
                log.info(f"Install with: sudo apt install gcc-aarch64-linux-gnu")
                return False
            except Exception as e:
                log.warn(f"Could not create stub: {e}")
                return False
    
    def run_interactive(self, max_iter: int = 100):
        """Main interactive loop"""
        log.header("QEMU Iterative Debugger")
        print(f"  Binary:  {self.qemu.binary}")
        print(f"  Arch:    {self.qemu.arch}")
        print(f"  Chroot:  {self.qemu.chroot}")
        print(f"  Output:  {self.outdir}")
        
        # Validate binary exists
        binary_rel = self.qemu.binary.lstrip('/')
        binary_full = self.qemu.chroot / binary_rel
        if not binary_full.exists():
            log.error(f"Binary not found: {binary_full}")
            log.info(f"Note: -b should be the path INSIDE the chroot, e.g., /usr/sbin/vj_generic")
            sys.exit(1)
        
        # Check for missing libraries
        missing_libs = self.check_libraries()
        if missing_libs:
            log.warn(f"Missing libraries detected:")
            for lib in missing_libs:
                # Try to find it elsewhere in the chroot
                found = self.find_library_in_chroot(lib)
                if found:
                    print(f"    {C.Y}?{C.E} {lib}  (found at: {found})")
                else:
                    print(f"    {C.R}✗{C.E} {lib}")
            print()
            
            print(f"{C.Y}Options:{C.E}")
            print("  1. Continue anyway (will fail at runtime)")
            print("  2. Try to create stub libraries")
            print("  3. Quit and fix manually")
            
            choice = input(f"\n{C.G}Choice [1-3]: {C.E}").strip()
            
            if choice == '2':
                for lib in missing_libs:
                    # First check if found elsewhere
                    found = self.find_library_in_chroot(lib)
                    if found:
                        # Symlink it to /usr/lib
                        target = self.qemu.chroot / 'usr' / 'lib' / lib
                        if not target.exists():
                            try:
                                rel_path = os.path.relpath(found, target.parent)
                                subprocess.run(['sudo', 'ln', '-sf', str(found), str(target)], check=True)
                                log.ok(f"Linked {lib} -> {found}")
                            except Exception as e:
                                log.warn(f"Could not link: {e}")
                    else:
                        self.create_stub_library(lib)
            elif choice == '3':
                log.info("Tips:")
                log.info("  - Find the library from another firmware or SDK")
                log.info("  - Copy to chroot: sudo cp libfoo.so /path/to/chroot/usr/lib/")
                log.info("  - Or use LD_PRELOAD with a stub")
                sys.exit(1)
            elif choice != '1':
                sys.exit(1)
        
        self.load()
        
        # Preflight check - run without GDB to catch library errors
        log.info("Running preflight check...")
        ok, error_info = self.qemu.preflight_check()
        
        if not ok:
            # Check if it's a library error
            if error_info and not error_info.startswith('/') and '.so' in error_info:
                missing_lib = error_info
                log.error(f"Missing library: {missing_lib}")
                
                # Handle missing library
                fail = Failure(FailType.LIB_MISSING)
                fail.info['missing_lib'] = missing_lib
                self.prompt(fail, f"Library not found: {missing_lib}")
                
                # After handling, re-run preflight
                return self.run_interactive(max_iter)
            elif error_info:
                log.error(f"Preflight failed: {error_info[:200]}")
        else:
            log.ok("Preflight passed")
        
        # Analyze binary and add hooks
        self.analyze_binary()
        self.auto_add_hooks()
        
        while self.iteration < max_iter:
            success, output, fail = self.run()
            
            if success:
                log.header("SUCCESS!")
                self.save()
                
                print(f"GDB script: {self.script_path}")
                print(f"\nTo run manually:")
                print(f"  sudo chroot {self.qemu.chroot} /{self.qemu.cfg['qemu']} -g {self.qemu.port} {self.qemu.binary}")
                print(f"  {self.qemu.cfg['gdb']} -x {self.script_path}")
                return
            
            rule = self.prompt(fail, output)
            
            if rule:
                # Remove existing rule at same address
                self.rules = [r for r in self.rules if r.addr != rule.addr]
                self.rules.append(rule)
                log.ok(f"Added: {rule.comment}")
                self.save()
        
        log.warn(f"Max iterations ({max_iter}) reached")


# ============================================================================
# Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="QEMU Iterative Debugger - Build GDB scripts to run embedded executables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -c /path/to/rootfs -b /usr/bin/service -a arm
  %(prog)s -c ./fs -b /bin/httpd -a mipsel -p 2345
  %(prog)s -c ./rootfs -b /sbin/daemon -a arm64 -o ./session

The tool will:
  1. Analyze the binary for hookable functions
  2. Run under QEMU with GDB attached
  3. Detect failures and prompt for fixes
  4. Build a cumulative GDB script
  5. Iterate until success
        """
    )
    
    parser.add_argument('-c', '--chroot', required=True, help='Rootfs path')
    parser.add_argument('-b', '--binary', required=True, help='Binary path (in chroot)')
    parser.add_argument('-a', '--arch', required=True, choices=list(ARCHS.keys()), help='Architecture')
    parser.add_argument('-p', '--port', type=int, default=1234, help='GDB port (default: 1234)')
    parser.add_argument('-o', '--output', default='./qemu_session', help='Output directory')
    parser.add_argument('--args', nargs=argparse.REMAINDER, default=[],
                       help='Arguments to pass to the binary (everything after --args)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--reset', action='store_true', help='Clear previous state')
    parser.add_argument('--max-iter', type=int, default=100, help='Max iterations')
    
    args = parser.parse_args()
    
    # Validate
    chroot = Path(args.chroot)
    if not chroot.exists():
        log.error(f"Chroot not found: {chroot}")
        sys.exit(1)
    
    Logger.VERBOSE = args.verbose
    
    # Create components
    qemu = QEMU(
        chroot=args.chroot,
        binary=args.binary,
        arch=args.arch,
        port=args.port,
        args=args.args
    )
    
    debugger = IterDebugger(qemu, outdir=args.output)
    
    if args.reset and debugger.state_path.exists():
        debugger.state_path.unlink()
        log.info("State cleared")
    
    try:
        debugger.run_interactive(max_iter=args.max_iter)
    except KeyboardInterrupt:
        print("\nInterrupted")
        debugger.save()
        sys.exit(1)


if __name__ == '__main__':
    main()

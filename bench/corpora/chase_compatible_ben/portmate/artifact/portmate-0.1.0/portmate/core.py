"""
Core functionality for port checking and process management
"""

import psutil
import socket
from typing import List, Dict, Optional, Tuple


def check_port(port: int) -> Dict[str, any]:
    """
    Check if a port is in use and get details about the process using it.
    
    Args:
        port: Port number to check
    
    Returns:
        Dictionary with port status and process information
    """
    result = {
        "port": port,
        "in_use": False,
        "process": None,
        "pid": None,
        "name": None,
        "status": None,
    }
    
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port:
                result["in_use"] = True
                result["status"] = conn.status
                
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        result["pid"] = conn.pid
                        result["name"] = process.name()
                        
                        # Safely get process info
                        try:
                            exe = process.exe()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            exe = "N/A"
                        
                        try:
                            username = process.username()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            username = "N/A"
                        
                        try:
                            cmdline = " ".join(process.cmdline()) if process.cmdline() else "N/A"
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            cmdline = "N/A"
                        
                        result["process"] = {
                            "pid": conn.pid,
                            "name": process.name(),
                            "exe": exe,
                            "status": process.status(),
                            "username": username,
                            "create_time": process.create_time(),
                            "cmdline": cmdline,
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        result["pid"] = conn.pid
                        result["name"] = "Access Denied"
                break
    except (psutil.AccessDenied, PermissionError):
        # Need elevated privileges to see all connections
        pass
    
    return result


def find_process_by_port(port: int) -> Optional[Dict]:
    """
    Find the process using a specific port.
    
    Args:
        port: Port number to check
    
    Returns:
        Process information dictionary or None
    """
    result = check_port(port)
    return result.get("process") if result["in_use"] else None


def kill_process_by_port(port: int, force: bool = False) -> Tuple[bool, str]:
    """
    Kill the process using a specific port.
    
    Args:
        port: Port number
        force: Use SIGKILL instead of SIGTERM
    
    Returns:
        Tuple of (success, message)
    """
    result = check_port(port)
    
    if not result["in_use"]:
        return False, f"Port {port} is not in use"
    
    if not result["pid"]:
        return False, f"Cannot determine process using port {port}"
    
    try:
        process = psutil.Process(result["pid"])
        process_name = process.name()
        
        if force:
            process.kill()  # SIGKILL
        else:
            process.terminate()  # SIGTERM
        
        process.wait(timeout=5)  # Wait for process to terminate
        return True, f"Successfully killed process '{process_name}' (PID: {result['pid']}) using port {port}"
    except psutil.NoSuchProcess:
        return False, f"Process {result['pid']} no longer exists"
    except psutil.AccessDenied:
        return False, f"Access denied. Try running with sudo/administrator privileges"
    except psutil.TimeoutExpired:
        if not force:
            return kill_process_by_port(port, force=True)
        return False, f"Process {result['pid']} did not terminate"
    except Exception as e:
        return False, f"Error killing process: {str(e)}"


def scan_ports(start_port: int = 1, end_port: int = 65535, only_used: bool = True) -> List[Dict]:
    """
    Scan a range of ports and return information about them.
    
    Args:
        start_port: Starting port number
        end_port: Ending port number
        only_used: Only return ports that are in use
    
    Returns:
        List of port information dictionaries
    """
    results = []
    used_ports = set()
    
    try:
        # Get all connections at once for efficiency
        for conn in psutil.net_connections(kind='inet'):
            if start_port <= conn.laddr.port <= end_port:
                used_ports.add(conn.laddr.port)
    except (psutil.AccessDenied, PermissionError):
        # Try to get what we can
        pass
    
    for port in sorted(used_ports):
        port_info = check_port(port)
        if only_used and not port_info["in_use"]:
            continue
        results.append(port_info)
    
    return results


def get_common_ports() -> Dict[int, str]:
    """
    Get a dictionary of commonly used ports and their services.
    
    Returns:
        Dictionary mapping port numbers to service names
    """
    return {
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP (submission)",
        993: "IMAPS",
        995: "POP3S",
        3000: "Node.js/React Dev Server",
        3001: "Node.js Alt Port",
        3306: "MySQL",
        5000: "Flask Dev Server",
        5432: "PostgreSQL",
        5500: "Live Server",
        5672: "RabbitMQ",
        6379: "Redis",
        8000: "Django Dev Server",
        8080: "HTTP Proxy/Alt",
        8443: "HTTPS Alt",
        8888: "Jupyter Notebook",
        9000: "Various Dev Servers",
        27017: "MongoDB",
        3389: "RDP",
        5900: "VNC",
    }


def get_all_listening_ports() -> List[Dict]:
    """
    Get all ports that are currently listening for connections.
    
    Returns:
        List of dictionaries with port and process information
    """
    listening = []
    seen_ports = set()
    
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN' and conn.laddr.port not in seen_ports:
                seen_ports.add(conn.laddr.port)
                port_info = check_port(conn.laddr.port)
                listening.append(port_info)
    except (psutil.AccessDenied, PermissionError) as e:
        # Re-raise with helpful message
        raise PermissionError(
            "Access denied. Try running with elevated privileges:\n"
            "  sudo portcheck --list"
        ) from e
    
    return sorted(listening, key=lambda x: x['port'])


def is_port_available(port: int) -> bool:
    """
    Check if a port is available (not in use).
    
    Args:
        port: Port number to check
    
    Returns:
        True if port is available, False otherwise
    """
    result = check_port(port)
    return not result["in_use"]

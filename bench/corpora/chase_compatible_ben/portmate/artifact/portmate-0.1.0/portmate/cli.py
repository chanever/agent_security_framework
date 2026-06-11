"""
Command-line interface for PortMate
"""

import argparse
import sys
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate

from . import __version__
from .core import (
    check_port,
    kill_process_by_port,
    scan_ports,
    get_common_ports,
    get_all_listening_ports,
    is_port_available,
)

# Initialize colorama for cross-platform colored output
init(autoreset=True)


def format_timestamp(timestamp: float) -> str:
    """Format Unix timestamp to readable string."""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def print_port_info(port_info: dict, verbose: bool = False):
    """Print formatted port information."""
    port = port_info['port']
    
    if not port_info['in_use']:
        print(f"{Fore.GREEN}✓ Port {port} is available{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.RED}● Port {port} is IN USE{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Status:{Style.RESET_ALL} {port_info['status']}")
    
    if port_info['process']:
        proc = port_info['process']
        print(f"{Fore.CYAN}PID:{Style.RESET_ALL} {proc['pid']}")
        print(f"{Fore.CYAN}Process:{Style.RESET_ALL} {proc['name']}")
        print(f"{Fore.CYAN}User:{Style.RESET_ALL} {proc['username']}")
        
        if verbose:
            print(f"{Fore.CYAN}Executable:{Style.RESET_ALL} {proc['exe']}")
            print(f"{Fore.CYAN}Started:{Style.RESET_ALL} {format_timestamp(proc['create_time'])}")
            print(f"{Fore.CYAN}Command:{Style.RESET_ALL} {proc['cmdline']}")
            print(f"{Fore.CYAN}Process Status:{Style.RESET_ALL} {proc['status']}")


def cmd_check(args):
    """Handle the check command."""
    for port in args.ports:
        port_info = check_port(port)
        print_port_info(port_info, verbose=args.verbose)
        if len(args.ports) > 1:
            print()  # Empty line between multiple ports


def cmd_kill(args):
    """Handle the kill command."""
    port = args.port
    
    # Show what we're about to kill
    port_info = check_port(port)
    if not port_info['in_use']:
        print(f"{Fore.YELLOW}Port {port} is not in use{Style.RESET_ALL}")
        return
    
    print(f"Port {port} is being used by:")
    print(f"  PID: {port_info['pid']}")
    print(f"  Process: {port_info['name']}")
    
    # Ask for confirmation unless --yes flag is provided
    if not args.yes:
        response = input(f"\n{Fore.YELLOW}Kill this process? [y/N]:{Style.RESET_ALL} ")
        if response.lower() not in ['y', 'yes']:
            print("Cancelled")
            return
    
    success, message = kill_process_by_port(port, force=args.force)
    if success:
        print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")
        sys.exit(1)


def cmd_scan(args):
    """Handle the scan command."""
    print(f"Scanning ports {args.start} to {args.end}...")
    
    ports = scan_ports(args.start, args.end, only_used=True)
    
    if not ports:
        print(f"{Fore.GREEN}No ports in use in the specified range{Style.RESET_ALL}")
        return
    
    # Prepare table data
    common_ports = get_common_ports()
    table_data = []
    
    for port_info in ports:
        port = port_info['port']
        service = common_ports.get(port, "")
        process_name = port_info['name'] if port_info['name'] else "N/A"
        pid = port_info['pid'] if port_info['pid'] else "N/A"
        status = port_info['status'] if port_info['status'] else "N/A"
        
        table_data.append([port, service, process_name, pid, status])
    
    headers = ["Port", "Service", "Process", "PID", "Status"]
    print(f"\n{Fore.CYAN}Found {len(ports)} port(s) in use:{Style.RESET_ALL}\n")
    print(tabulate(table_data, headers=headers, tablefmt="simple"))


def cmd_list(args):
    """Handle the list command."""
    print("Fetching all listening ports...")
    
    listening_ports = get_all_listening_ports()
    
    if not listening_ports:
        print(f"{Fore.GREEN}No listening ports found{Style.RESET_ALL}")
        return
    
    common_ports = get_common_ports()
    table_data = []
    
    for port_info in listening_ports:
        port = port_info['port']
        service = common_ports.get(port, "")
        process_name = port_info['name'] if port_info['name'] else "N/A"
        pid = port_info['pid'] if port_info['pid'] else "N/A"
        
        if args.verbose and port_info['process']:
            cmdline = port_info['process']['cmdline']
            table_data.append([port, service, process_name, pid, cmdline[:60] + "..."])
        else:
            table_data.append([port, service, process_name, pid])
    
    headers = ["Port", "Service", "Process", "PID"]
    if args.verbose:
        headers.append("Command")
    
    print(f"\n{Fore.CYAN}Found {len(listening_ports)} listening port(s):{Style.RESET_ALL}\n")
    print(tabulate(table_data, headers=headers, tablefmt="simple"))


def cmd_find(args):
    """Handle the find command to find available port."""
    start = args.start
    preferred = args.preferred
    
    if preferred:
        if is_port_available(preferred):
            print(f"{Fore.GREEN}✓ Port {preferred} is available{Style.RESET_ALL}")
            return
        else:
            print(f"{Fore.YELLOW}Port {preferred} is in use, searching for alternatives...{Style.RESET_ALL}")
    
    # Find next available port
    for port in range(start, 65536):
        if is_port_available(port):
            common = get_common_ports()
            service = f" ({common[port]})" if port in common else ""
            print(f"{Fore.GREEN}✓ Available port found: {port}{service}{Style.RESET_ALL}")
            return
    
    print(f"{Fore.RED}No available ports found{Style.RESET_ALL}")


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="portmate",
        description="A powerful CLI tool to check ports, find processes, and manage port usage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  portmate 3000              Check if port 3000 is in use
  portmate 8080 8000 5000    Check multiple ports
  portmate --kill 3000       Kill process using port 3000
  portmate --scan            Scan common ports
  portmate --list            List all listening ports
  portmate --find 3000       Find available port starting from 3000
  
Shortcuts:
  pm (alias for portmate)
        """
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"portmate {__version__}",
    )
    
    parser.add_argument(
        "ports",
        nargs="*",
        type=int,
        metavar="PORT",
        help="Port number(s) to check",
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed information",
    )
    
    parser.add_argument(
        "-k", "--kill",
        type=int,
        metavar="PORT",
        help="Kill the process using the specified port",
    )
    
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Force kill (SIGKILL instead of SIGTERM)",
    )
    
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompts",
    )
    
    parser.add_argument(
        "-s", "--scan",
        action="store_true",
        help="Scan a range of ports",
    )
    
    parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Start port for scanning (default: 1)",
    )
    
    parser.add_argument(
        "--end",
        type=int,
        default=10000,
        help="End port for scanning (default: 10000)",
    )
    
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List all listening ports",
    )
    
    parser.add_argument(
        "--find",
        type=int,
        metavar="START",
        help="Find an available port starting from START",
    )
    
    parser.add_argument(
        "--preferred",
        type=int,
        metavar="PORT",
        help="Preferred port to check first (use with --find)",
    )
    
    args = parser.parse_args()
    
    # Handle different commands
    try:
        if args.kill:
            args.port = args.kill
            cmd_kill(args)
        elif args.scan:
            cmd_scan(args)
        elif args.list:
            cmd_list(args)
        elif args.find:
            args.start = args.find
            cmd_find(args)
        elif args.ports:
            cmd_check(args)
        else:
            parser.print_help()
            sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Cancelled{Style.RESET_ALL}")
        sys.exit(130)
    except PermissionError as e:
        print(f"{Fore.RED}{str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    except psutil.AccessDenied:
        print(f"{Fore.RED}Permission denied. Try running with sudo/administrator privileges:{Style.RESET_ALL}")
        print(f"  sudo portmate {' '.join(sys.argv[1:])}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

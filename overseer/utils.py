"""
Utility functions for Overseer
Includes tool discovery and file operations
"""
import os
import platform
from pathlib import Path
from typing import Optional, Dict, List


script_cwd = os.path.dirname(os.path.abspath(__file__))

def file_exists(path: Optional[str]) -> bool:
    """Check if a file exists at the given path"""
    return path is not None and os.path.isfile(path)


def get_default_tool_locations() -> Dict[str, List[str]]:
    """
    Get default installation locations for analysis tools based on OS
    Returns a dictionary mapping tool names to lists of potential paths
    """
    system = platform.system()
    home = Path.home()
    
    # Common tool locations by operating system
    locations = {
        # Static Analysis Tools
        "capa": [],
        "yara": [],
        "exiftool": [],
        "die": [],  # Detect It Easy
        "floss": [],
        "resourcehacker": [],
        "binwalk": [],
        
        # Dynamic Analysis Tools
        "fakenet": [],
        "procdump": [],
        "procmon": [],
        "ttd": [],  # Time Travel Debugging
    }
    
    if system == "Windows":
        # Windows default locations
        locations["capa"] = [
            r"C:\Program Files\capa\capa.exe",
            r"C:\Tools\capa\capa.exe",
            str(home / "Desktop" / "Tools" / "capa" / "capa.exe"),
        ]
        locations["yara"] = [
            r"C:\Program Files\yara\yara64.exe",
            r"C:\Tools\yara\yara64.exe",
            str(home / "Desktop" / "Tools" / "yara" / "yara64.exe"),
        ]
        locations["exiftool"] = [
            r"C:\Program Files\exiftool\exiftool.exe",
            r"C:\Tools\exiftool\exiftool.exe",
            str(home / "Desktop" / "Tools" / "exiftool" / "exiftool.exe"),
        ]
        locations["die"] = [
            r"C:\Program Files\DIE\die.exe",
            r"C:\Tools\DIE\die.exe",
            str(home / "Desktop" / "Tools" / "DIE" / "die.exe"),
            str(home / "Desktop" / "Tools" / "Detect-it-Easy" / "die.exe"),
        ]
        locations["floss"] = [
            r"C:\Program Files\floss\floss.exe",
            r"C:\Tools\floss\floss.exe",
            str(home / "Desktop" / "Tools" / "floss" / "floss.exe"),
        ]
        locations["resourcehacker"] = [
            r"C:\Program Files\Resource Hacker\ResourceHacker.exe",
            r"C:\Tools\ResourceHacker\ResourceHacker.exe",
            str(home / "Desktop" / "Tools" / "ResourceHacker" / "ResourceHacker.exe"),
        ]
        locations["binwalk"] = [
            r"C:\Program Files\binwalk\binwalk.exe",
            r"C:\Tools\binwalk\binwalk.exe",
            str(home / "Desktop" / "Tools" / "binwalk" / "binwalk.exe"),
        ]
        locations["fakenet"] = [
            r"C:\Program Files\FakeNet-NG\fakenet.exe",
            r"C:\Tools\FakeNet-NG\fakenet.exe",
            str(home / "Desktop" / "Tools" / "FakeNet-NG" / "fakenet.exe"),
        ]
        locations["procdump"] = [
            r"C:\Program Files\SysinternalsSuite\procdump.exe",
            r"C:\Tools\SysinternalsSuite\procdump.exe",
            r"C:\Tools\procdump\procdump.exe",
            str(home / "Desktop" / "Tools" / "SysinternalsSuite" / "procdump.exe"),
        ]
        locations["procmon"] = [
            r"C:\Program Files\SysinternalsSuite\Procmon.exe",
            r"C:\Tools\SysinternalsSuite\Procmon.exe",
            r"C:\Tools\Procmon\Procmon.exe",
            str(home / "Desktop" / "Tools" / "SysinternalsSuite" / "Procmon.exe"),
        ]
        locations["ttd"] = [
            r"C:\Program Files\Windows Kits\10\Debuggers\x64\TTD\TTD.exe",
            r"C:\Tools\TTD\TTD.exe",
            str(home / "Desktop" / "Tools" / "TTD" / "TTD.exe"),
        ]
    
    elif system == "Darwin":  # macOS
        locations["capa"] = [
            "/usr/local/bin/capa",
            "/opt/homebrew/bin/capa",
            str(home / "Desktop" / "Tools" / "capa" / "capa"),
        ]
        locations["yara"] = [
            "/usr/local/bin/yara",
            "/opt/homebrew/bin/yara",
            str(home / "Desktop" / "Tools" / "yara" / "yara"),
        ]
        locations["exiftool"] = [
            "/usr/local/bin/exiftool",
            "/opt/homebrew/bin/exiftool",
            str(home / "Desktop" / "Tools" / "exiftool" / "exiftool"),
        ]
        locations["binwalk"] = [
            "/usr/local/bin/binwalk",
            "/opt/homebrew/bin/binwalk",
            str(home / "Desktop" / "Tools" / "binwalk" / "binwalk"),
        ]
    
    elif system == "Linux":
        locations["capa"] = [
            "/usr/local/bin/capa",
            "/usr/bin/capa",
            str(home / "Desktop" / "Tools" / "capa" / "capa"),
        ]
        locations["yara"] = [
            "/usr/local/bin/yara",
            "/usr/bin/yara",
            str(home / "Desktop" / "Tools" / "yara" / "yara"),
        ]
        locations["exiftool"] = [
            "/usr/local/bin/exiftool",
            "/usr/bin/exiftool",
            str(home / "Desktop" / "Tools" / "exiftool" / "exiftool"),
        ]
        locations["binwalk"] = [
            "/usr/local/bin/binwalk",
            "/usr/bin/binwalk",
            str(home / "Desktop" / "Tools" / "binwalk" / "binwalk"),
        ]
    
    return locations


def find_tool(tool_name: str, custom_path: Optional[str] = None) -> Optional[str]:
    """
    Find a tool executable by searching:
    1. Custom path (if provided)
    2. Environment variables (PATH)
    3. Default OS-specific locations
    
    Args:
        tool_name: Name of the tool to find (e.g., 'capa', 'yara')
        custom_path: Optional custom path to check first
    
    Returns:
        Full path to the tool executable, or None if not found
    """
    # Check custom path first
    if custom_path and file_exists(custom_path):
        return custom_path
    
    # Check if it's already an absolute path
    if custom_path and os.path.isabs(custom_path):
        if file_exists(custom_path):
            return custom_path
    
    # Normalize tool name to lowercase
    tool_name_lower = tool_name.lower()
    
    # Common executable extensions by OS
    system = platform.system()
    extensions = [".exe", ".bat"] if system == "Windows" else ["", ".sh"]
    
    # Check PATH environment variable
    for path in os.environ.get('PATH', '').split(os.pathsep):
        for ext in extensions:
            tool_path = os.path.join(path.strip('"'), tool_name + ext)
            if file_exists(tool_path):
                return tool_path
    
    # Check default locations
    default_locations = get_default_tool_locations()
    if tool_name_lower in default_locations:
        for location in default_locations[tool_name_lower]:
            if file_exists(location):
                return location
    
    # Check script directory
    for ext in extensions:
        local_path = os.path.join(script_cwd, tool_name + ext)
        if file_exists(local_path):
            return local_path
    
    return None


def discover_all_tools() -> Dict[str, Optional[str]]:
    """
    Discover all analysis tools and return their paths
    
    Returns:
        Dictionary mapping tool names to their discovered paths (or None if not found)
    """
    tool_names = [
        "capa", "yara", "exiftool", "die", "floss", 
        "resourcehacker", "binwalk", "fakenet", "procdump", 
        "procmon", "ttd"
    ]
    
    discovered = {}
    for tool in tool_names:
        discovered[tool] = find_tool(tool)
    
    return discovered


def file_finder(executable: str) -> Optional[str]:
    """
    Legacy function for backward compatibility
    Searches for an executable in PATH and script directory
    """
    if file_exists(executable):
        return executable

    for path in os.environ.get('PATH', '').split(os.pathsep):
        exe_path = os.path.join(path.strip('"'), executable)
        if file_exists(exe_path):
            return exe_path

    local_path = os.path.join(script_cwd, executable)
    if file_exists(local_path):
        return local_path

    return None
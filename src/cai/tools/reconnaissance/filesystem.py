"""
Here are the CLI tools for executing commands.
"""

from cai.tools.common import run_command  # pylint: disable=E0401
from cai.sdk.agents import function_tool

# Dangerous flags that enable RCE, file writes, or file deletion
DANGEROUS_FIND_FLAGS = {
    "-exec", "-execdir", "-ok", "-okdir",
    "-delete",
    "-fprintf", "-fprint", "-fls", "-fprint0",
    "-print0",
}

@function_tool
def list_dir(path: str, args: str = "", ctf=None) -> str:
    """
    List the contents of a directory.
    by def .
    Args:
        path: The directory path to list contents from
        args: Additional arguments to pass to the ls command

    Returns:
        str: The output of running the ls command
    """
    command = f'ls {path} {args}'
    return run_command(command, ctf=ctf)

@function_tool
def cat_file(file_path: str, args: str = "", ctf=None) -> str:
    """
    Display the contents of a file.

    Args:
        args: Additional arguments to pass to the cat command
        file_path: Path to the file to display contents of

    Returns:
        str: The output of running the cat command
    """
    command = f'cat {args} {file_path} '
    return run_command(command, ctf=ctf)


# FileSearchTool
# ListDirTool
# TextSearchTool
# FileAnalysisTool
# StringExtractionTool
# ReadFileTool
# FilePermissionsTool
# FileCompressionTool

@function_tool
def pwd_command(ctf=None) -> str:
    """
    Retrieve the current working directory.

    Returns:
        str: The absolute path of the current working directory
    """
    command = 'pwd'
    return run_command(command, ctf=ctf)

@function_tool
def find_file(file_path: str, args: str = "", ctf=None) -> str:
    """
    Find a file in the filesystem.
    """
    # Block dangerous flags that enable RCE, file writes, or deletion
    for flag in DANGEROUS_FIND_FLAGS:
        if flag in args:
            return f"Error: DANGEROUS flag '{flag}' is not allowed"
    
    command = f'find {file_path} {args}'
    return run_command(command, ctf=ctf)

@function_tool
def eza_list(path: str = ".", args: str = "-la", ctf=None) -> str:
    """
    List directory contents using eza (modern ls replacement with better formatting).
    
    Args:
        path: Directory path to list (default: current directory ".")
        args: Additional eza arguments (default: "-la" for long format with hidden files)
              Common options: -la (long, all), -T (tree), -s=size (sort by size), --git-ignore
    
    Returns:
        str: Formatted directory listing with colors and icons
    """
    # Check if eza is available, fallback to ls if not
    import shutil
    if shutil.which("eza"):
        command = f'eza {args} {path}'
    else:
        # Fallback to ls with similar arguments
        command = f'ls {args} {path}'
    return run_command(command, ctf=ctf)

@function_tool
def less_file(file_path: str, args: str = "", ctf=None) -> str:
    """
    View file contents with less (pager for large files).
    
    Args:
        file_path: Path to the file to view
        args: Additional less arguments (e.g., "-N" for line numbers, "-S" to chop long lines)
    
    Returns:
        str: File contents (less will output all content in non-interactive mode)
    """
    # In non-interactive mode, less behaves like cat
    # Use -F to exit immediately if file fits on one screen, -X to not clear screen
    command = f'less {args} -FX {file_path}'
    return run_command(command, ctf=ctf)

@function_tool
def change_directory(path: str, ctf=None) -> str:
    """
    Change the current working directory.
    
    Note: This changes directory for subsequent commands in the same session.
    Use pwd_command() to verify the current directory.
    
    Args:
        path: Directory path to change to (absolute or relative)
    
    Returns:
        str: Confirmation message with the new directory path
    """
    import os
    if not os.path.exists(path):
        return f"ERROR: Directory does not exist: {path}"
    if not os.path.isdir(path):
        return f"ERROR: Path is not a directory: {path}"
    
    # Change directory and verify
    try:
        os.chdir(path)
        new_path = os.getcwd()
        return f"Changed directory to: {new_path}"
    except Exception as e:
        return f"ERROR: Failed to change directory: {e}"

@function_tool
def read_file_lines(file_path: str, start_line: int = 1, num_lines: int = 50, ctf=None) -> str:
    """
    Read specific lines from a file (useful for large files).
    
    Args:
        file_path: Path to the file
        start_line: Line number to start reading from (1-indexed, default: 1)
        num_lines: Number of lines to read (default: 50)
    
    Returns:
        str: The requested lines from the file
    """
    end_line = start_line + num_lines - 1
    command = f'sed -n "{start_line},{end_line}p" {file_path}'
    return run_command(command, ctf=ctf)

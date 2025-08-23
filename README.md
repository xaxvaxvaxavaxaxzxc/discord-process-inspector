# discord-process-inspector
dc @ binaryinformative

discord-memory-scraper
A Windows utility that extracts Discord username and user ID from process memory using the Windows API. Built with C++17 for educational exploration of low-level process inspection.
Features

Scans Discord process memory for username and user ID.
Supports verbose logging with --verbose flag.
Thread-safe and RAII-based for robust resource management.

Requirements

Windows OS
C++17-compliant compiler (MSVC, MinGW)
Administrator privileges
Discord running with a logged-in user

Build Instructions
MSVC
cl /EHsc /std:c++17 src/discord_mem_scraper.cpp /link psapi.lib

MinGW
g++ -std=c++17 src/discord_mem_scraper.cpp -o discord_mem_scraper -lpsapi

Usage
Run as administrator:
discord_mem_scraper.exe

For detailed logs:
discord_mem_scraper.exe --verbose

Example output:
discord username: myuser
discord user id: 123456789012345678

Warning
Memory scraping may violate Discord’s Terms of Service and local laws (e.g., DMCA, CFAA). This project is for educational purposes only. Use only on your own system with explicit permission. The author is not responsible for misuse.
License
MIT License. See LICENSE for details.

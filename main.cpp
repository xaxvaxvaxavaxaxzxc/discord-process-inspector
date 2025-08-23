#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <sstream>
#include <iomanip>
#include <iostream>
#pragma comment(lib, "psapi.lib")

class logger {
public:
    enum class level { info, warning, error };
    static void log(level lvl, const std::string& msg) {
        static std::mutex log_mutex;
        std::lock_guard<std::mutex> lock(log_mutex);
        std::ostream& out = (lvl == level::error) ? std::cerr : std::cout;
        out << "[" << get_timestamp() << "] ";
        switch (lvl) {
        case level::info: out << "info: "; break;
        case level::warning: out << "warning: "; break;
        case level::error: out << "error: "; break;
        }
        out << msg << std::endl;
    }

private:
    static std::string get_timestamp() {
        auto now = std::time(nullptr);
        std::tm time_info;
#ifdef _MSC_VER
        if (localtime_s(&time_info, &now) != 0) {
            return "unknown_time";
        }
#else
        time_info = *std::localtime(&now);
#endif
        std::stringstream ss;
        ss << std::put_time(&time_info, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

class handle_guard {
public:
    explicit handle_guard(HANDLE handle) : handle_(handle) {}
    ~handle_guard() { if (handle_ != INVALID_HANDLE_VALUE) CloseHandle(handle_); }
    handle_guard(const handle_guard&) = delete;
    handle_guard& operator=(const handle_guard&) = delete;
    HANDLE get() const { return handle_; }

private:
    HANDLE handle_;
};

class memory_scanner {
public:
    explicit memory_scanner(HANDLE process) : process_(process) {
        GetSystemInfo(&sys_info_);
    }

    std::string scan_for_pattern(const std::string& pattern) const {
        char* addr = static_cast<char*>(sys_info_.lpMinimumApplicationAddress);
        char* max_addr = static_cast<char*>(sys_info_.lpMaximumApplicationAddress);
        MEMORY_BASIC_INFORMATION mem_info;

        while (addr < max_addr) {
            if (!VirtualQueryEx(process_, addr, &mem_info, sizeof(mem_info))) {
                logger::log(logger::level::warning, "virtualqueryex failed at address " + std::to_string((uintptr_t)addr));
                addr += sys_info_.dwPageSize;
                continue;
            }

            if (mem_info.State == MEM_COMMIT &&
                (mem_info.Protect & (PAGE_READWRITE | PAGE_READONLY)) &&
                !(mem_info.Protect & PAGE_GUARD)) {
                std::vector<char> buffer(mem_info.RegionSize);
                SIZE_T bytes_read;
                if (ReadProcessMemory(process_, mem_info.BaseAddress, buffer.data(), mem_info.RegionSize, &bytes_read)) {
                    for (size_t i = 0; i < bytes_read - pattern.size(); ++i) {
                        if (memcmp(buffer.data() + i, pattern.c_str(), pattern.size()) == 0) {
                            size_t start = i + pattern.size();
                            size_t end = start;
                            while (end < bytes_read && buffer[end] != '"' && buffer[end] != '\0') {
                                ++end;
                            }
                            if (end > start) {
                                return std::string(buffer.data() + start, end - start);
                            }
                        }
                    }
                }
                else {
                    logger::log(logger::level::warning, "readprocessmemory failed at " + std::to_string((uintptr_t)mem_info.BaseAddress));
                }
            }
            addr += mem_info.RegionSize;
        }
        return "";
    }

private:
    HANDLE process_;
    SYSTEM_INFO sys_info_;
};

class discord_inspector {
public:
    discord_inspector() = default;

    std::vector<DWORD> find_discord_pids() const {
        std::vector<DWORD> pids;
        PROCESSENTRY32W pe = { sizeof(pe) };
        handle_guard snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (snap.get() == INVALID_HANDLE_VALUE) {
            logger::log(logger::level::error, "failed to create process snapshot: " + std::to_string(GetLastError()));
            return pids;
        }

        if (Process32FirstW(snap.get(), &pe)) {
            do {
                std::string name = wstring_to_string(pe.szExeFile);
                for (char& c : name) c = std::tolower(c);
                if (name.find("discord") != std::string::npos) {
                    pids.push_back(pe.th32ProcessID);
                    logger::log(logger::level::info, "found discord process with pid: " + std::to_string(pe.th32ProcessID));
                }
            } while (Process32NextW(snap.get(), &pe));
        }
        else {
            logger::log(logger::level::error, "process32firstw failed: " + std::to_string(GetLastError()));
        }
        return pids;
    }

    std::string get_username() const {
        return extract_data({ "\"username\":\"" });
    }

    std::string get_user_id() const {
        return extract_data({ "\"id\":\"", "\"user_id\":\"" });
    }

private:
    static std::string wstring_to_string(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
        if (size_needed == 0) {
            logger::log(logger::level::error, "widechartomultibyte failed: " + std::to_string(GetLastError()));
            return "";
        }
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &str[0], size_needed, nullptr, nullptr);
        return str;
    }

    std::string extract_data(const std::vector<std::string>& patterns) const {
        auto pids = find_discord_pids();
        if (pids.empty()) {
            logger::log(logger::level::warning, "no discord processes found");
            return "unknown";
        }

        for (DWORD pid : pids) {
            handle_guard ph(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid));
            if (!ph.get()) {
                logger::log(logger::level::error, "failed to open process " + std::to_string(pid) + ": " + std::to_string(GetLastError()));
                continue;
            }

            memory_scanner scanner(ph.get());
            for (const auto& pattern : patterns) {
                std::string result = scanner.scan_for_pattern(pattern);
                if (!result.empty()) {
                    logger::log(logger::level::info, "found data for pattern " + pattern + ": " + result);
                    return result;
                }
            }
        }
        logger::log(logger::level::warning, "no data found for patterns");
        return "unknown";
    }
};

int main(int argc, char* argv[]) {
    try {
        discord_inspector inspector;
        bool verbose = argc > 1 && std::string(argv[1]) == "--verbose";
        std::string username = inspector.get_username();
        std::string user_id = inspector.get_user_id();

        if (!verbose) {
            std::cout << "discord username: " << username << "\n";
            std::cout << "discord user id: " << user_id << "\n";
        }
    }
    catch (const std::exception& e) {
        logger::log(logger::level::error, "unexpected error: " + std::string(e.what()));
        return 1;
    }
    return 0;
}

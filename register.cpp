#include <sys/user.h>
#include <sys/ptrace.h>
#include <algorithm>
#include "register.h"
using namespace std;

uint64_t get_register_value(pid_t pid, reg r) {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    auto it = find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
        [r](auto&& rd) { return rd.r == r; });
    
    return *(reinterpret_cast<uint64_t*>(&regs) + (it - g_register_descriptors.begin()));
}

void set_register_value(pid_t pid, reg r, uint64_t value) {
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    auto it = find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
        [r](auto&& rd) { return rd.r == r; });

    *(reinterpret_cast<uint64_t*>(&regs) + (it - g_register_descriptors.begin()))
        = value;
    
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned regnum) {
    auto it = find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
        [regnum](auto&& rd) { return rd.dwarf_r == regnum; });
    if (it == g_register_descriptors.end()) {
        throw out_of_range("Unknown dwarf register");
    }

    return get_register_value(pid, it->r);
}

string get_register_name(reg r) {
    auto it = find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
        [r](auto&& rd) { return rd.r == r; });
    return it->name;
}

reg get_register_from_name(const string& name) {
    auto it = find_if(g_register_descriptors.begin(), g_register_descriptors.end(),
        [name](auto&& rd) { return rd.name == name; });
    
    return it->r;
}


#include <iostream>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/user.h>
using namespace std;

class breakpoint {
public:
    breakpoint() {}
    breakpoint(pid_t pid, intptr_t addr) 
        : m_pid(pid), m_addr(addr), m_enabled(false), m_saved_data()
    {}

    void enable();
    void disable();

    bool is_enabled() const { return m_enabled; }
    intptr_t get_address() const { return m_addr; }

private:
    pid_t m_pid;
    intptr_t m_addr;
    bool m_enabled;
    uint8_t m_saved_data;
};
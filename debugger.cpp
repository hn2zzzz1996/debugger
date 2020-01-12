#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <iomanip>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "linenoise.h"
#include "breakpoint.h"
#include "register.h"
using namespace std;

class debugger {
public:
	debugger (string prog_name, pid_t pid)
		: m_prog_name(move(prog_name)), m_pid(pid) {}

	void run();
	void handle_command(const string &line);
	void continue_execution();
	void set_breakpoint_at_address(intptr_t addr);
	void delete_breakpoint_at_address(intptr_t addr);
	void dump_registers();
	uint64_t read_memory(uint64_t address);
	void write_memory(uint64_t address, uint64_t value);
	uint64_t get_pc();
	void set_pc(uint64_t pc);
	void step_over_breakpoint();
	int wait_for_signal();

private:
	string m_prog_name;
	pid_t m_pid;
	unordered_map<intptr_t, breakpoint> m_breakpoints;
};

vector<string> split(const string &s, char delimiter) {
	vector<string> out;
	stringstream ss(s);
	string item;

	while (getline(ss, item, delimiter)) {
		out.push_back(item);
	}

	return out;
}

bool is_prefix(const string &s, const string of) {
	if (s.size() > of.size()) return false;
	return equal(s.begin(), s.end(), of.begin());
}

void debugger::run() {
	wait_for_signal();

	char *line = nullptr;
	while ((line = linenoise("minidbg> ")) != nullptr) {
		handle_command(line);
		linenoiseHistoryAdd(line);
		linenoiseFree(line);
	}
}

void debugger::handle_command(const string &line) {
	auto args = split(line, ' ');
	auto command = args[0];

	if (is_prefix(command, "continue")) {
		continue_execution();
	} else if (is_prefix(command, "breakpoint")) {
		string addr(args[1], 2);
		set_breakpoint_at_address(stol(addr, 0, 16));
	} else if (is_prefix(command, "quit")) {
		exit(0);
	} else if(is_prefix(command, "register")) {
		if (is_prefix(args[1], "dump")) {
			dump_registers();
		} else if(is_prefix(args[1], "read")) {
			cout << get_register_value(m_pid, get_register_from_name(args[2]))
				<< endl;
		} else if(is_prefix(args[1], "write")) {
			string val(args[3], 2);
			set_register_value(m_pid, get_register_from_name(args[2]), 
				stol(val, 0, 16));
		}
	} else if(is_prefix(command, "memory")) {
		string addr(args[2], 2);
		if (is_prefix(args[1], "read")) {
			cout << hex << read_memory(stol(addr, 0, 16)) << endl;
		} else if (is_prefix(args[1], "write")) {
			string val(args[3], 2);
			write_memory(stol(addr, 0, 16), stol(val, 0, 16));
		}
	}
	else {
		cerr << "Unknown command\n";
	}
}

void debugger::continue_execution() {
	step_over_breakpoint();
	ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
	int status = wait_for_signal();
	if (WIFEXITED(status)) {
		cout << "Process Exited!" << endl;
		exit(1);
	}
}

void debugger::set_breakpoint_at_address(intptr_t addr) {
	cout << "Set breakpoint at address 0x" << hex << addr << std::endl;
	breakpoint bp(m_pid, addr);
	bp.enable();
	m_breakpoints[addr] = bp;
}

void debugger::delete_breakpoint_at_address(intptr_t addr) {
	
}

void debugger::dump_registers() {
	for (const auto& rd : g_register_descriptors) {
		cout << rd.name << " 0x" << setw(16) << hex << 
			get_register_value(m_pid, rd.r) << endl;
	}
}

uint64_t debugger::read_memory(uint64_t address) {
	return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
	ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t debugger::get_pc() {
	return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
	set_register_value(m_pid, reg::rip, pc);
}

void debugger::step_over_breakpoint() {
	uint64_t previous_breakpoint_address = get_pc() - 1;

	if (m_breakpoints.count(previous_breakpoint_address)) {
		breakpoint &bp = m_breakpoints[previous_breakpoint_address];
		set_pc(previous_breakpoint_address);

		/* 如果运行到这里，前面一个字节一定是断点，如果先被撤销了，就不用恢复了 */
		if (bp.is_enabled()) {
			bp.disable();
			ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
			wait_for_signal();
			bp.enable();
		}
	}
}

int debugger::wait_for_signal() {
	int status;
	int options = 0;
	waitpid(m_pid, &status, options);
	return status;
}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		cerr << "Program name not sprcified" << endl;
		return -1;
	}
	auto prog = argv[1];

	auto pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
		execl(prog, prog, nullptr);
	} else if (pid >= 1) {
		debugger dbg(prog, pid);
		dbg.run();
	}
}

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <fstream>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "libelfin/elf/elf++.hh"
#include "libelfin/dwarf/dwarf++.hh"

#include "linenoise.h"
#include "breakpoint.h"
#include "register.h"
using namespace std;

class debugger {
public:
	debugger (string prog_name, pid_t pid)
		: m_prog_name(move(prog_name)), m_pid(pid) {
			auto fd = open(m_prog_name.c_str(), O_RDONLY);

			m_elf = elf::elf(elf::create_mmap_loader(fd));
			m_dwarf = dwarf::dwarf(dwarf::elf::create_loader(m_elf));
		}

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
	void check_breakpoint_and_revocer_pc();

	siginfo_t get_signal_info();
	void handle_sigtrap(siginfo_t info);

	dwarf::die get_function_from_pc(uint64_t pc);
	dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);
	void print_source(const string &file_name, unsigned line, unsigned 
		n_lines_context = 10);

private:
	string m_prog_name;
	pid_t m_pid;
	unordered_map<intptr_t, breakpoint> m_breakpoints;

	dwarf::dwarf m_dwarf;
	elf::elf m_elf;
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
		// check_breakpoint_and_revocer_pc();
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
	} else if(is_prefix(command, "delete")) {
		string addr(args[1], 2);
		delete_breakpoint_at_address(stol(addr, 0, 16));
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
	if (m_breakpoints.count(addr)) {
		breakpoint &bp = m_breakpoints[addr];
		bp.disable();
		m_breakpoints.erase(addr);
		cout << "Delete breakpoint at address 0x" << hex << addr << endl;
	} else {
		cout << "Breakpoint at address 0x" << hex << addr << 
			" not exists!" << endl;
	}
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
	uint64_t previous_breakpoint_address = get_pc();

	if (m_breakpoints.count(previous_breakpoint_address)) {
		breakpoint &bp = m_breakpoints[previous_breakpoint_address];

		/* 如果运行到这里，前面一个字节一定是断点，如果先被撤销了，就不用恢复了 */
		if (bp.is_enabled()) {
			bp.disable();
			ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
			wait_for_signal();
			bp.enable();
		}
	}
}

void debugger::check_breakpoint_and_revocer_pc() {
	uint64_t previous_breakpoint_address = get_pc() - 1;

	if (m_breakpoints.count(previous_breakpoint_address)) {
		set_pc(previous_breakpoint_address);
	}
}

int debugger::wait_for_signal() {
	int status;
	int options = 0;
	waitpid(m_pid, &status, options);

	siginfo_t siginfo = get_signal_info();
	switch (siginfo.si_signo) {
		case SIGTRAP:
			handle_sigtrap(siginfo);
			break;
		case SIGSEGV:
			cout << "Yay, segfault, Reason: " << siginfo.si_code << endl;
			break;
		case SIGQUIT:
			cout << "Debugged programm exited!" << endl;
			break;
		default:
			cout << "Unknown signal number: " << siginfo.si_signo << endl;
			cout << "Got signal " << strsignal(siginfo.si_signo) << endl;
	}

	return status;
}

siginfo_t debugger::get_signal_info() {
	siginfo_t info;
	ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
	return info;
}

void debugger::handle_sigtrap(siginfo_t info) {
	switch (info.si_code) {
		// one of these will be set if a breakpoint was hit
		case SI_KERNEL:
		case TRAP_BRKPT:
		{
			set_pc(get_pc() - 1);
			cout << "Hit breakpoint at address 0x" << hex << get_pc() << endl;
			auto line_entry = get_line_entry_from_pc(get_pc());
			print_source(line_entry->file->path, line_entry->line);
			return;
		}
		// this will be set if the signal was sent by single stepping
		case TRAP_TRACE:
			return;
		default:
			cout << "Unknown SIGTRAP code " << info.si_code << endl;
			return;
	}
}

/**
 * 从当前rip位置获取在哪个函数内部
 * （未处理inline函数（函数内部可能还有inline函数））
 */
dwarf::die debugger::get_function_from_pc(uint64_t pc) {
	// 首先遍历每一个编译单元
	for (const dwarf::compilation_unit &cu : m_dwarf.compilation_units()) {
		// 每一个编译单元的第一个die说明了该编译单元的一些信息，
		// 主要使用这个编译单元的地址范围
		if (dwarf::die_pc_range(cu.root()).contains(pc)) {
			for (const dwarf::die &die : cu.root()) {
				if (die.tag == dwarf::DW_TAG::subprogram) {
					if (dwarf::die_pc_range(die).contains(pc)) {
						return die;
					}
				}
			}
		}
	}

	throw std::out_of_range("Cannot find function");
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
	for (const dwarf::compilation_unit &cu : m_dwarf.compilation_units()) {
		if (dwarf::die_pc_range(cu.root()).contains(pc)) {
			const dwarf::line_table &lt = cu.get_line_table();
			auto it = lt.find_address(pc);
			if (it == lt.end()) {
				throw std::out_of_range("Cannot find line entry");
			} else {
				return it;
			}
		}
	}

	throw std::out_of_range("Cannot find line entry");
}

/**
 * n_lines_context: 显示line行前面与后面各n_lines_context行 
 */
void debugger::print_source(const string &file_name, unsigned line,
	 unsigned n_lines_context) {
	ifstream file(file_name);

	unsigned start_line = (line <= n_lines_context ? 1 : line - n_lines_context);
	unsigned end_line = line + n_lines_context + (line < n_lines_context ? 
		n_lines_context - line : 0) + 1;
	
	char c;
	unsigned current_line = 1u;
	while (current_line != start_line && file.get(c)) {
		if (c == '\n') {
			current_line++;
		}
	}

	cout << (current_line == start_line ? "> " : "  ");

	while (current_line <= end_line && file.get(c)) {
		cout << c;
		if (c == '\n') {
			current_line++;
			cout << (current_line == line ? "> " : "  ");
		}
	}

	// Write newline and make sure that the stream is flushed properly
	cout << endl;
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

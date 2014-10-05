import lldb
import subprocess
import re
import tempfile
import pipes
import os
import ast
import macholib.mach_o
import macholib.MachO
import struct

def lldb_run(command):
	res = lldb.SBCommandReturnObject()
	lldb.debugger.GetCommandInterpreter().HandleCommand(command, res)
	return res

def lldb_call(command):
	res = lldb_run('call ' + command)
	out = res.GetOutput()
	r = re.compile(r'^[^=]*= (.*)\n$')
	m = r.search(out)
	return m.groups()[0]

def	__lldb_init_module(debugger, internal_dict):
	def add_command(name):
		lldb_run('command script add -f utils.{0} {0}'.format(name))
	
	add_command('objc_symbols')
	add_command('break_entry')
	add_command('intel_parse')
	add_command('entrypoint')
	add_command('break_message')
	
	# Remove the color prompt added by lldbinit
	lldb_run('settings set prompt "(lldb) "')

def current_target():
	return lldb.debugger.GetSelectedTarget().executable.fullpath

def otool_get(bin, name):
	otool_output = subprocess.check_output(['otool', '-l', bin])
	match = re.search(name + '\s+(\S*)', otool_output)
	if not match:
		raise Exception('Couldn\'t get info from otool!')
	
	return match.groups()[0]

def fix_uuid(main_bin, symbol_bin):
	main_uuid = otool_get(main_bin, 'uuid')
	
	subprocess.check_call(['replace_uuid', symbol_bin, main_uuid])

def objc_symbols(debugger, command, result, internal_dict):
	#print 'This command doesn\'t currently work!'
	#return
	
	target_path = current_target()
	
	if not target_path:
		print 'No target path available'
		return
	
	symbol_file = tempfile.mkstemp()[1]
	
	subprocess.check_output('objc-symbols {} | SymTabCreator -o {}'.format(pipes.quote(target_path), pipes.quote(symbol_file)), shell=True)
	
	fix_uuid(target_path, symbol_file)
	
	print symbol_file
	
	#lldb_run('add-dsym {}'.format(pipes.quote(symbol_file)))
	
	#os.unlink(symbol_file)

def get_arch():
	return lldb.debugger.GetSelectedTarget().triple.split('-')[0]

def get_cputype():
	return (key for key, value in macholib.mach_o.CPU_TYPE_NAMES.items() if value == get_arch()).next()

def get_macho_header():
	m = macholib.MachO.MachO(current_target())
	cputype = get_cputype()
	header = (h for h in m.headers if h.header.cputype == cputype).next()
	return header

def get_load_cmd(header, kind, properties={}):
	for c in header.commands:
		if isinstance(c[1], kind):
			correct_cmd = True
			p = c[1].__dict__['_objects_']
			for k in properties:
				if properties[k] != p[k]:
					correct_cmd = False
					break
			
			if correct_cmd:
				return c
	
	return None

def array_from_str(t, str, n=None, **kw):
	t_size = t._size_
	
	if n == None:
		assert len(str) % t_size == 0, 'String length isn\'t a multiple of type size'
		n = len(str) / t_size
	else:
		assert n >= 1, 'n must be positive'
		assert len(str) >= n * t_size, 'String too short'
	
	arr = []
	
	for i in range(0, n * t_size, t_size):
		arr.append(t.from_str(str[i:i + t_size], **kw))
	
	return arr

def get_registers(cmd_tuple):
	lc, cmd, data = cmd_tuple
	
	x86_THREAD_STATE32 = 0x1
	x86_THREAD_STATE64 = 0x4
	
	if not hasattr(cmd, 'flavor'):
		flavor, count = array_from_str(macholib.ptypes.p_uint32, data, 2)
		data = data[macholib.ptypes.p_uint32._size_ * 2:]
	else:
		flavor = int(cmd.flavor)
		count = int(cmd.count)
	
	if flavor == x86_THREAD_STATE32:
		register_names = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp', 'ss', 'eflags', 'eip', 'cs', 'ds', 'es', 'fs', 'gs']
		register_type = macholib.ptypes.p_uint32
	elif flavor == x86_THREAD_STATE64:
		register_names = ['rip', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'rflags', 'cs', 'fs', 'gs']
		register_type = macholib.ptypes.p_uint64
	else:
		return None
	
	register_size = macholib.ptypes.sizeof(register_type)
	expected_data_size = register_size * len(register_names)
	
	assert count * 4 == expected_data_size, 'Flavor doesn\'t match count'
	assert len(data) == expected_data_size, 'Count doesn\'t match length data'
	
	registers = {}
	
	for offset, name in zip(range(0, len(data), register_size), register_names):
		registers[name] = register_type.from_str(data[offset:offset + register_size]) # Doesn't work currently: _endian_=cmd._endian_
	
	return registers

def get_entrypoint():
	header = get_macho_header()
	
	if header.MH_MAGIC == macholib.mach_o.MH_MAGIC_64:
		is64bit = True
	elif header.MH_MAGIC == macholib.mach_o.MH_MAGIC:
		is64bit = False
	else:
		raise Exception('Unknown MH_MAGIC in header!')
	
	thread_command = get_load_cmd(header, macholib.mach_o.thread_command)
	if thread_command:
		if is64bit:
			# return get_registers(thread_command)['rip']
			
			rip_offset = 2 * 4 + 16 * 8
			return struct.unpack(header.endian + 'Q', thread_command[2][rip_offset:rip_offset+8])[0]
		else:
			# return get_registers(thread_command)['eip']
			
			eip_offset = 2 * 4 + 10 * 4
			return struct.unpack(header.endian + 'L', thread_command[2][eip_offset:eip_offset+4])[0]
	
	entry_point_command = get_load_cmd(header, macholib.mach_o.entry_point_command)
	if entry_point_command:
		offset = entry_point_command[1].entryoff
		
		segment_kind =  macholib.mach_o.segment_command_64 if is64bit else  macholib.mach_o.segment_command
		text_segment = get_load_cmd(header, segment_kind, {'segname': '__TEXT' + 10 * '\x00'})
		
		return offset + text_segment[1].vmaddr
	
	return None
	
def entrypoint(debugger, command, result, internal_dict):
	if not current_target():
		print 'No target path available'
		return
	
	entrypoint = get_entrypoint()
	print 'Entrypoint at 0x{:x}'.format(entrypoint)

def break_entry(debugger, command, result, internal_dict):
	if not current_target():
		print 'No target path available'
		return
	
	entrypoint = get_entrypoint()
	if not entrypoint:
		print 'Couldn\'t find entrypoint'
		return
	
	lldb_run('breakpoint set -a {}'.format(entrypoint))

def intel_parse(debugger, command, result, internal_dict):	
	r = re.compile(r'\[([^\[\]]*)\]')
	output = command
	while True:
		new = r.sub(r'*((unsigned long *)(\1))', output)
		if new == output:
			break
		
		output = new
	
	print output

def break_message(debugger, command, result, internal_dict):
	r = re.compile(r'([+-])\s*\[\s*(\S+)\s+([^\]]+)\]')
	m = r.search(command)
	if not m:
		print 'Error in message format!'
		return
	
	typ, cls, sel = m.groups()
	sel = re.sub(r'\s+', '', sel)

	meta = typ == '+'
	
	clsptr = lldb_call('(id)objc_getClass("{}")'.format(cls))
	if clsptr == 'nil':
		print "Couldn't find class: " + cls
		return
	
	selptr = lldb_call('(id)sel_registerName("{}")'.format(sel))
	if selptr == 'nil':
		print "Couldn't register selector: " + sel
		return

	func = 'class_getClassMethod' if meta else 'class_getInstanceMethod'
	method = lldb_call('(id){}({}, {})'.format(func, clsptr, selptr))
	if method == 'nil':
		print "Couldn't find method for: " + sel
		return

	imp = lldb_call('(id)method_getImplementation({})'.format(method))
	
	lldb_run('breakpoint set -a {}'.format(imp))


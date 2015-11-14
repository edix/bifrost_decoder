'''
Bifrost Rat Config Decoder
'''


__description__ = 'Bifrost RAT Decoder'
__author__ = '@xedi25'
__version__ = '0.1'
__date__ = '2015/11'

#Standard Imports Go Here
import os
import sys
import struct
from optparse import OptionParser


# Main Decode Function Goes Here
'''
data is a read of the file
Must return a python dict of values
'''
def run(f):
	config_dict = {}
	try:
		#
		# get settings length
		#
		f.seek(-4, 2)
		SettingSize = struct.unpack('<L', f.read(4))[0]

		if (SettingSize - 4 >= 0x10000 or SettingSize == 0):
			print "Invalid settings size: {0} bytes".format({f.size})
			return
		
		config_dict['Settings Size'] = SettingSize
		
		#
		# get data and test if correct bifrost settings
		#
		f.seek(0 - 4 - SettingSize, 2)
		
		ok = f.read(5)
		key = f.read(16)
		
		SettingSize -= (5 + 16)
		
		okstring = "_ok_\0"
		
		okresult = decode_data(ok, key)
		
		if (okresult == okstring):
			print "[+] Found Bifrost < v1.2"
			
			#
			# decode older bifrost versions
			#
			decode_old_bifost(f, SettingSize, key, config_dict)
		else:
		
			#
			# try new bifrost
			#
			KeyEncryption = "\x50\x65\xc5\x00"
			
			DecryptedKey = decode_data2(key, KeyEncryption, 0x2f)
			okresult = decode_data2(ok, DecryptedKey, 0x12)
			
			if (okresult == okstring):
				print "[+] Found Bifrost >= v1.2"
				decode_new_bifrost(f, DecryptedKey, config_dict)
			
 

		return config_dict

	except Exception as e:
		print "Exception: ", str(e)
		return
		
def decode_old_bifost(f, SettingSize, key, config_dict):
	for x in range(3):
		len_host = struct.unpack('<h', f.read(2))[0]
		#
		# decrypt ips
		#
		hostname = decode_data(f.read(len_host), key)
		config_dict['Host ' + str(x + 1)] = hostname
		
		SettingSize -= (len_host + 2)
	#	
	# encryption key in hex
	#
	config_dict['Encryption Key'] = "".join("{:02x}".format(ord(c)) for c in key) 
	
	#
	# decrypt settings block
	#
	db = f.read(SettingSize)
	d = decode_data(db, key)

	config_dict['Port'] = struct.unpack('<L', d[0:4])[0]
	
	#
	# these are the settings if eg: write to registry, keylogger, etc. try and error and you will figure it out
	#
	config_dict['Startup: ActiveX'] = struct.unpack('<B', d[4])[0]
	config_dict['Startup: Run Local Machine'] = struct.unpack('<B', d[5])[0]
	config_dict['Startup: Run Current User'] = struct.unpack('<B', d[6])[0]
	config_dict['Melt'] = struct.unpack('<B', d[7])[0]
	config_dict['Installation Directory (0 = Sys, 1 = Win)'] = struct.unpack('<B', d[8])[0]
	config_dict['Delayed Startup'] = struct.unpack('<B', d[9])[0]
	
	# remove everything after first null character
	config_dict['Start key'] = d[10:10+16].split('\0', 1)[0]
	config_dict['Password'] = d[26:26+8].split('\0', 1)[0]
	config_dict['Filename'] = d[34:34+16].split('\0', 1)[0]
	config_dict['Assigned Name'] = d[50:50+15].split('\0', 1)[0]
	
	# unknown data in hex
	config_dict['unknown7'] = "".join("{:02x}".format(ord(c)) for c in d[66:])
	
	return config_dict


def decode_new_bifrost(f, key, config_dict):
	#
	# get main settings block
	#
	data = f.read(0x144)
	d = decode_data2(data, key, 0x5d)

	#
	# read ips
	#
	ipcount = struct.unpack('<L', d[0x20:0x24])[0]
	for i in range(ipcount):
		ip = f.read(0x20)
		ipdecoded = decode_data2(ip, key, 0x0)
		config_dict['IP ' + str(i + 1)] = ipdecoded.split('\0', 1)[0]
	
	#
	# read sockets
	#
	sockscount = struct.unpack('<L', d[0x24:0x28])[0]
	for i in range(sockscount):
		socks = f.read(0x20)
		socksdecoded = decode_data2(socks, key, 0x0)
		config_dict['Socks ' + str(i + 1)] = socksdecoded.split('\0', 1)[0]
		
		socksport = f.read(0x4)
		socksportdecoded = decode_data2(socksport, key, 0x0)
		config_dict['Socks Port ' + str(i + 1)] = struct.unpack('<L', socksportdecoded)[0]
	
	#
	# parse settings
	#
	config_dict['Port'] = struct.unpack('<L', d[0x10:0x14])[0]
	config_dict['Socks'] = struct.unpack('<B', d[0x14])[0]
	config_dict['Password'] = d[0x15:0x15 + 8].split('\0', 1)[0]
	config_dict['IP Count'] = struct.unpack('<L', d[0x20:0x24])[0]
	config_dict['Socks Count'] = struct.unpack('<L', d[0x24:0x28])[0]
	config_dict['Filename'] = d[0x28:0x28 + 0x10].split('\0', 1)[0]
	config_dict['Directory'] = d[0x38:0x38 + 0x10].split('\0', 1)[0]
	config_dict['Install Directory (0 = Programs, 1 = Sys, 2 = Win)'] = struct.unpack('<B', d[0x48])[0]
	
	config_dict['Autostart'] = struct.unpack('<B', d[0x4c])[0]
	config_dict['Registry'] = d[0x4d:0x4d + 0x28].split('\0', 1)[0]
	config_dict['Registry Key'] = d[0x75:0x75 + 0x10].split('\0', 1)[0]
	
	config_dict['Persistence'] = struct.unpack('<B', d[0x85])[0]
	config_dict['Include Extension'] = struct.unpack('<B', d[0x86])[0]
	
	config_dict['Extension Name'] = d[0x87:0x87 + 0x10].split('\0', 1)[0]
	config_dict['Offline Keylogger'] = d[0x97:0x97 + 0x10].split('\0', 1)[0]
	
	config_dict['Keylogger'] = struct.unpack('<B', d[0xA7])[0]
	config_dict['Keylogger: Exclude Shift'] = struct.unpack('<B', d[0xA8])[0]
	config_dict['Keylogger: Exclude Backspace'] = struct.unpack('<B', d[0xA9])[0]
	config_dict['Injection'] = struct.unpack('<B', d[0xAA])[0]
	
	config_dict['Process Name'] = d[0xAB:0xAB + 0x10].split('\0', 1)[0]
	config_dict['Assigned Name'] = d[0xBB:0xBB + 0x10].split('\0', 1)[0]
	config_dict['Mutex Name'] = d[0xCB:0xCB + 0x10].split('\0', 1)[0]
	
	config_dict['Stealth mode (0 = Visible, 1 = Cautious, 2 = Aggressive)'] = struct.unpack('<B', d[0xD4])[0]
	config_dict['Set hidden'] = struct.unpack('<B', d[0xD8])[0]
	config_dict['Set older date'] = struct.unpack('<B', d[0xD9])[0]
	
	config_dict['Melt'] = struct.unpack('<B', d[0xDA])[0]
	
	config_dict['Delayed connection (0 = No delay, 1 = On Next Reboot, 2 = Delay)'] = struct.unpack('<B', d[0xDC])[0]
	config_dict['Delay days'] = struct.unpack('<L', d[0xE0:0xE0 + 4])[0]
	config_dict['Delay hours'] = struct.unpack('<L', d[0xE4:0xE4 + 4])[0]
	config_dict['Delay minutes'] = struct.unpack('<L', d[0xE8:0xE8 + 4])[0]
	
	config_dict['Kernel Unhooking'] = struct.unpack('<B', d[0xEC])[0]
	config_dict['Hide process'] = struct.unpack('<B', d[0xEE])[0]
	
	config_dict['Tor'] = struct.unpack('<B', d[0xEF])[0]
	config_dict['Include Plugin'] = struct.unpack('<B', d[0xF0])[0]
	
	

#Helper Functions Go Here
def decode_data(data, key):
	new_string = ''
	k = 0
	for i in range(len(data)):
		val = ord(data[i])
		xor = val ^ ord(key[k])
		if (k >= 15):
			k = 0
		else:
			k = k + 1
		
		new_string += chr(xor)

	return new_string
	

def decode_data2(data, key, kstart):
	new_string = ''
	
	tab1 = []
	tab2 = []
	
	for i in range(0x100):
		tab1.append(i)

	k = 0
	for i in range(0x100):
		tab2.append(ord(key[k]))
		if (k >= len(key) - 1):
			k = 0
		else:
			k = k + 1

	#
	# shuffle around
	#
	a = 0
	b = 0

	for i in range(0x100):
		a = tab1[i]
		b = (b + tab1[i] + tab2[i]) & 0xff
		tab1[i] = tab1[b]
		tab1[b] = a
	
	#
	# decrypt the string with the table
	#
	j = 0
	k = 0
	for i in range(len(data)):
		j = (j + 1) & 0xff
		
		a = tab1[j]
		k = (k + a) & 0xff
		b = (tab1[k])
		
		tab1[j] = b
		tab1[k] = a
		
		xor = tab1[(a + b) & 0xff]
		val = xor ^ ((ord(data[i]) + kstart) & 0xff)
		new_string += chr(val)

	return new_string

# Main
if __name__ == "__main__":
	parser = OptionParser(usage='usage: %prog inFile outConfig\n' + __description__, version='%prog ' + __version__)
	(options, args) = parser.parse_args()
	
	# If we dont have args quit with help page
	if len(args) > 0:
		pass
	else:
		parser.print_help()
		sys.exit()
	try:
		print "[+] Reading file {0}".format(args[0])
		f = open(args[0], 'rb')
	except:
		print "[+] Couldn't Open File {0}".format(args[0])
		sys.exit()
	
	#Run the config extraction
	print "[+] Searching for Config"
	config = run(f)
	
	#If we have a config figure out where to dump it out.
	if config == None:
		print "[+] Config not found"
		sys.exit()
		
	#if you gave me two args im going to assume the 2nd arg is where you want to save the file
	if len(args) == 2:
		print "[+] Writing Config to file {0}".format(args[1])
		with open(args[1], 'a') as outFile:
			for key, value in sorted(config.iteritems()):
				outFile.write("Key: {0}\t Value: {1}\n".format(key,value))
				
	# if no seconds arg then assume you want it printing to screen
	else:
		print "[+] Printing Config to screen"
		for key, value in sorted(config.iteritems()):
			print "   [-] Key: {0}\t Value: {1}".format(key,value)
		print "[+] End of Config"
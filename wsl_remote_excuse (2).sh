#!/usr/bin/expect  -- 
#####
#proc_scp to scp2 pub key
#####
proc proc_scp {IP TIMES} {
#puts "debug:scp TIMES:$TIMES\n"
set YESNOFLAG 0
spawn /usr/local/bin/scp2 -P 36000 /etc/ssh2/hostkey.pub mqq@$IP#36000:/usr/local/app/.ssh2/hostkeys/key_36000_$IP.pub
expect 	{

	"assword:" {
	return 0
	}
	
	"yes/no)?" {
		set YESNOFLAG 1
		send "yes\r"
	}

	"Authentication failed" {
		puts "\nCHECKERROR: Authentication failed!!!\n"
		return 4
	}
	
	"Interrupted system call" {
		if { $TIMES < 8 } {
		#puts "debug:scp TIMES:$TIMES\n"
		set ret_code [proc_scp $IP [expr $TIMES + 1]]
		return $ret_code 
		}
		return 1
	}
	"FATAL" {
		puts "\nCHECKERROR: $IP occur FATAL ERROR!!!\n"
		return 1
	}

	timeout {
		puts "\nCHECKWARNING: $IP logon TIMEOUT!!!\n"
		return 3
	}
	
}

if { $YESNOFLAG == 1 } {
	expect {
		"assword:" {
			return 0
		}

		"yes/no)?" {
			set YESNOFLAG 2
			send "yes\r"
		}
		"FATAL" {
			puts "\nCHECKERROR: $IP occur FATAL ERROR!!!\n"
			return 1
		}
		"Authentication failed" {
			puts "\nCHECKERROR: Authentication failed!!!\n"
			return 4
		}
		"Interrupted system call" {
		if { $TIMES < 8 } {
		#puts "debug:scp TIMES:$TIMES\n"
		set ret_code [proc_scp $IP [expr $TIMES + 1]]
		#puts "debug:proc_scp ret_code:$ret_code\n"
		return $ret_code 
		}
		return 1
		}
		timeout {
			puts "\nCHECKWARNING: $IP logon TIMEOUT!!!\n"
			return 3
		}
	}
}

if { $YESNOFLAG == 2 } {
	expect {
		"assword:" {
			return 0
		}
	}
	return 1
}

return 1
}
#####
#proc_ssh to ssh a server
#####
proc proc_ssh {IP USER PASSWD SHELL TIMEOUT TIMES} {

set timeout $TIMEOUT 
set YESNOFLAG 0
set PASSWDFLAG 0
puts "$SHELL\n"
spawn ssh2 -p36000 $IP -l$USER -q 
	   
expect 	{

	"assword:" {
		send "$PASSWD\r" 
		set PASSWDFLAG 1
	}
	
	"yes/no)?" {
		set YESNOFLAG 1
		send "yes\r"
	}

	"Authentication failed" {
		puts "\nCHECKERROR: Authentication failed!!!\n"
		return 4
	}
	
	"Interrupted system call" {
		if { $TIMES < 8 } {
		#puts "debug:TIMES:$TIMES\n"
		set ret_code [proc_ssh $IP $USER $PASSWD $SHELL $TIMEOUT [expr $TIMES + 1]]
		#puts "debug:proc_ssh ret_code:$ret_code\n"
		return $ret_code 
		}
		return 1
	}
	"using non-current uid but not initialized" {
		set proc_scp_ret [proc_scp $IP 1]
		if { $proc_scp_ret == 0 } {
		set ret_code [proc_ssh $IP $USER $PASSWD $SHELL $TIMEOUT [expr $TIMES + 1]]
		#puts "debug:proc_ssh ret_code:$ret_code\n"
		return $ret_code
		}
		return 1
	}
	"FATAL" {
		puts "\nCHECKERROR: $IP occur FATAL ERROR!!!\n"
		return 1
	}
	"Connection Refused" {
		puts "\nCHECKERROR: $IP Connection Refused!!!\n"
		exit 1
	}

	"Connection refused" {
		puts "\nCHECKERROR: $IP Connection Refused!!!\n"
		exit 1
	}
	"No route to host" {
		puts "\nCHECKERROR: $IP No route to host!!!\n"
		exit 1
	}

	timeout {
		puts "\nCHECKWARNING: $IP logon TIMEOUT!!!\n"
		return 3
	}
	
}

if { $YESNOFLAG == 1 } {
	expect {
		"assword:" {
			send "$PASSWD\r"
			set PASSWDFLAG 1
		}

		"yes/no)?" {
			set YESNOFLAG 2
			send "yes\r"
		}
		"using non-current uid but not initialized" {
			set proc_scp_ret [proc_scp $IP 1]
			if { $proc_scp_ret == 0 } {
			set ret_code [proc_ssh $IP $USER $PASSWD $SHELL $TIMEOUT [expr $TIMES + 1]]
			#puts "debug:proc_ssh ret_code:$ret_code\n"
			return $ret_code
			}
			return 1
		}
		"FATAL" {
			puts "\nCHECKERROR: $IP occur FATAL ERROR!!!\n"
			return 1
		}
		"Authentication failed" {
			puts "\nCHECKERROR: Authentication failed!!!\n"
			return 4 
		}
		"Interrupted system call" {
		if { $TIMES < 8 } {
		#puts "debug:TIMES:$TIMES\n"
		set ret_code [proc_ssh $IP $USER $PASSWD $SHELL $TIMEOUT [expr $TIMES + 1]]
		#puts "debug:proc_ssh ret_code:$ret_code\n"
		return $ret_code 
		}
		return 1
		}
		timeout {
			puts "\nCHECKWARNING: $IP logon TIMEOUT!!!\n"
			return 3
		}
	}
}

if { $YESNOFLAG == 2 } {
	expect {
		"assword:" {
			send "$PASSWD\r"
			set PASSWDFLAG 1
		}
		timeout {
			puts "\nCHECKWARNING: $IP logon TIMEOUT!!!\n"
			return 3
		}
	}
}

if { $PASSWDFLAG == 1 && $PASSWD != $USER } {
	expect {
		"assword:" {
			puts "ERROR:passwd error!\n"
			return 2
		}
		"$PASSWD" {
			expect {
				"assword:" {
				puts "ERROR:passwd error!\n"
				return 2
				}
				"$USER@" {
				send "echo \"Login succ.\"\r"
				}
				timeout {
				puts "\nssh time out!\n"
				return 3
				}	
			}
		}
			
		"$USER@" {
			send "echo \"Login succ.\"\r"
		}
		"Authentication failed" {
			puts "Authentication failed\n"
			return 4
		}
		timeout {
			puts "\nssh time out!\n"
			return 3
		}
	}
}

#only login ok can go here!
expect {
	"$USER@" {
		puts "$SHELL\n"
		send "$SHELL\r"
		expect "$USER@"
		#interact
		return 0
	}
	"Authentication failed" {
		puts "Authentication failed\n"
		return 4
	}
	timeout {
		puts "\nssh time out!\n"
		return 3
	}
}
}
#exec ". ./ssh.inc"

if { [llength $argv] < 4 } {
	puts "### USAGE:  $argv0  ip user passwd shell \[timeout\]"
	exit 1
}

set IP [lindex $argv 0]
set USER [lindex $argv 1]
set PASSWD [lindex $argv 2]
set SHELL [lindex $argv 3]
set TIMEOUT [lindex $argv 4]

if { [llength $TIMEOUT] == 0 } { 
	puts "注意：超时时间为空,默认60秒"
	set TIMEOUT 60
}

set proc_ssh_ret [proc_ssh $IP $USER $PASSWD $SHELL $TIMEOUT 1]
if { $proc_ssh_ret == 2 } {
puts "ERROR:passwd error!!!\n" 
exit  
}
if { $proc_ssh_ret != 0 } {
puts "ERROR:ssh occur a error!!!\n" 
exit  
}
exit  

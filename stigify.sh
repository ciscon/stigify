#!/bin/bash
# STIG enforcement script [EL6]
# SitScape - DG
# 11-19-14

#user configurable options:

#this will force the script to enable selinux if set to non-zero value
#note:this is not recommended, you should enable selinux before or after stigification manually to assure nothing breaks (which is likely).
enable_selinux=0

#remove xwindows environment if it exists
disable_xwin=1

#install and enable clamav
enable_clamav=1

#install and enable aide
enable_aide=1


logfile="/tmp/stig_`date +'%m-%d-%y-%T'`"
errorlog="/tmp/stig_err_`date +'%m-%d-%y-%T'`"


#determine which binary to use in displaying progress bar
if `which whiptail >/dev/null 2>&1`; then
  progress=`which whiptail`
elif  `which dialog >/dev/null 2>&1` ;then
  progress=`which dialog`
else
  echo "Initializing..."
  yum --skip-broken -y install newt >/dev/null 2>&1
  progress=`which whiptail`
  clear
fi


function catch_error()
{
if [ -e "$errorlog" ];then
  $progress --msgbox "`cat $errorlog`" 10 70
  exit 1
fi
}


function check_el_version {
el6=0
if [ -e /etc/redhat-release ];then
  el6=`grep " 6\." -c /etc/redhat-release`
fi

if [ $el6 -ne 1 ];then
    echo "Only EL 6 is supported by this script, exiting." > $errorlog
    exit 3
fi
}


function stig {
echo 0

  #fix log permissions
  chmod -f 755 /var/log

  if [ $enable_selinux -gt 0 ];then
echo 2
    yum -y install  policycoreutils  policycoreutils-python >>$logfile 2>&1
echo 3
    sed -i 's/SELINUX=.*$/SELINUX=enforcing/g' /etc/selinux/config
    echo 1 > /selinux/enforce
  fi
  #backup pam.d
  cp -a /etc/pam.d /etc/pam.d_stig_backup

  #remove compilers
  yum -y erase gcc gcc-c++ >>$logfile 2>&1

echo 5

  if [ $disable_xwin -gt 0 ];then  
    yum -y erase xorg-x11-server-common >>$logfile 2>&1
  fi

  #disable listening on 25, even on localhost
  if [ -e /etc/postfix/master.cf ];then

    sed -ie "s/\(^smtp.*inet.*\)/\#\1/g" /etc/postfix/master.cf >>$logfile 2>&1
    /etc/init.d/postfix restart >>$logfile 2>&1

  fi

echo 10

  #remove java source files
  if [ -e /var/www ];then
    find /var/www/ -name *.java -exec rm {} \; >>$logfile 2>&1
  fi
 
  #enable ntpd
  yum -y install ntp.x86_64 >>$logfile 2>&1
  chkconfig ntpd on >>$logfile 2>&1

  #enable auditd
  chkconfig auditd on >>$logfile 2>&1

echo 15

  #change audit behavior to send email
  sed -i 's/^space_left_action.*/space_left_action = EMAIL/g' /etc/audit/auditd.conf >>$logfile 2>&1
  #switch to single user mode when audit space too low
  sed -i 's/^disk_full_action.*/disk_full_action = SINGLE/g' /etc/audit/auditd.conf >>$logfile 2>&1
  #switch to single user mode when audit space too low
  sed -i 's/^admin_space_left_action.*/admin_space_left_action = SINGLE/g' /etc/audit/auditd.conf >>$logfile 2>&1
  #switch to single user mode when disk error occurs 
  sed -i 's/^disk_error_action.*/disk_error_action = SINGLE/g' /etc/audit/auditd.conf >>$logfile 2>&1
  #audit call adjtimex/timeofday
  if [ `grep -c -e '-a always,exit -F arch=b64 -S settimeofday -S adjtimex -S clock_settime -k audit_time_rules' /etc/audit/audit.rules` -eq 0 ];then
    echo "-a always,exit -F arch=b64 -S settimeofday -S adjtimex -S clock_settime -k audit_time_rules" >> /etc/audit/audit.rules 
  fi
echo 20



#start auditd for auditctl to work
  if [ -e /var/log/audit ];then
    chmod -f 0700 /var/log/audit
  fi
  if [ -e /etc/init.d/auditd ];then
    /etc/init.d/auditd start >>$logfile 2>&1
  fi
  #audit localtime
  if [ `auditctl -l | grep -c "watch=/etc/localtime"` -ne 1 ];then
    echo "-w /etc/localtime -p wa -k audit_time_rules" >> /etc/audit/audit.rules 
  fi
  #audit creation/modification
  if [ `auditctl -l | egrep -c '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)'` -eq 0 ];then 
    echo "-w /etc/group -p wa -k audit_account_changes 
-w /etc/passwd -p wa -k audit_account_changes
-w /etc/gshadow -p wa -k audit_account_changes
-w /etc/shadow -p wa -k audit_account_changes
-w /etc/security/opasswd -p wa -k audit_account_changes" >> /etc/audit/audit.rules 
  fi

  #make sure issue files exist
  touch /etc/issue /etc/issue.net /etc/hosts /etc/sysconfig/network >>$logfile 2>&1
  #audit network
  if [ `auditctl -l | egrep -c '(/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)'` -eq 0 ];then 
    echo "-a exit,always -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications" >> /etc/audit/audit.rules 
  fi
echo 25
  #audit selinux
  if [ `auditctl -l | grep -c "dir=/etc/selinux"` -eq 0 ];then
    echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules 

  fi
  #audit acl modifications
  if [ `auditctl -l | grep syscall | grep -c chmod` -eq 0 ];then
    echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S fremovexattr -S fsetxattr -S lchown -S lremovexattr -S lsetxattr -S removexattr -S setxattr  -S fchmodat -S fchmod -S chmod -F auid>=500 -F auid!=4294967295 -k perm_mod">>/etc/audit/audit.rules 
  fi
  #audit unauthorized access 
  if [ `grep -c EACCES /etc/audit/audit.rules` -eq 0 ];then
    echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate \
-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate \
-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access">>/etc/audit/audit.rules 
  fi
echo 30
  #audit all suid programs
  suid_programs=`find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null`
  for x in `echo $suid_programs`;do
    if [ `grep -c $x /etc/audit/audit.rules` -eq 0 ];then
      echo "-a always,exit -F path=$x -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged">>/etc/audit/audit.rules 
    fi
  done
  #audit mounts
  if [ `auditctl -l | grep syscall | grep -c mount` -eq 0 ];then 
    echo "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export">>/etc/audit/audit.rules 
  fi
echo 35
  #audit linking
  if [ `auditctl -l | grep -c unlink` -eq 0 ];then
    echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete">>/etc/audit/audit.rules 
  fi
  #audit sudoers
  if [ `auditctl -l | grep -c "watch=/etc/sudoers"` -eq 0 ];then
    echo "-w /etc/sudoers -p wa -k actions">>/etc/audit/audit.rules 
  fi
  #audit kernel modules
  if [ `auditctl -l | grep syscall | grep -c init_module` -eq 0 ];then
    echo "-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules">>/etc/audit/audit.rules 
  fi
  #forward audit records to syslog
  sed -i 's/.*active.*/active = yes/g' /etc/audisp/plugins.d/syslog.conf  >>$logfile 2>&1
echo 40
  

  #remove services
  yum -y erase xinetd >>$logfile 2>&1
  yum -y erase telnet-server >>$logfile 2>&1
  yum -y erase rsh-server >>$logfile 2>&1
  yum -y erase ypserv >>$logfile 2>&1
  yum -y erase tftp-server >>$logfile 2>&1

echo 50

  #disable services
  chkconfig rexec off >>$logfile 2>&1
  chkconfig rlogin off  >>$logfile 2>&1
  chkconfig ypbind off >>$logfile 2>&1
  chkconfig avahi-daemon off >>$logfile 2>&1
  chkconfig abrtd off >>$logfile 2>&1
  chkconfig atd off >>$logfile 2>&1
  chkconfig --level 0123456 autofs off >>$logfile 2>&1
  service autofs stop >>$logfile 2>&1
echo 55
  chkconfig ntpdate off >>$logfile 2>&1
  chkconfig oddjobd off >>$logfile 2>&1
  chkconfig qpidd off >>$logfile 2>&1
  chkconfig rdisc off >>$logfile 2>&1
  chkconfig netconsole off >>$logfile 2>&1
  chkconfig bluetooth off >>$logfile 2>&1
  service bluetooth stop >>$logfile 2>&1

echo 60

  #set default runlevel to 3
  sed -i 's/^id.*initdefault.*/id:3:initdefault:/g' /etc/inittab >>$logfile 2>&1

  #ssh daemon settings
  if [ -e /etc/ssh/sshd_config ];then
    sed -i '/^ClientAliveInterval.*$/d' /etc/ssh/sshd_config >>$logfile 2>&1
    echo "ClientAliveInterval 900" >> /etc/ssh/sshd_config 
    sed -i '/^ClientAliveCountMax.*$/d' /etc/ssh/sshd_config >>$logfile 2>&1
    echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config 
    sed -i '/^IgnoreRhosts.*$/d' /etc/ssh/sshd_config >>$logfile 2>&1
    echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config 
    sed -i '/^HostbasedAuthentication.*$/d' /etc/ssh/sshd_config >>$logfile 2>&1
    echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config 
    sed -i '/^PermitRootLogin.*$/d' /etc/ssh/sshd_config >>$logfile 2>&1
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config 
    sed -i '/^PermitEmptyPasswords.*$/d' /etc/ssh/sshd_config >>$logfile 2>&1
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config 
    sed -i '/^PermitUserEnvironment.*$/d' /etc/ssh/sshd_config >>$logfile 2>&1
    echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config 
    sed -i '/^Ciphers.*$/d' /etc/ssh/sshd_config >>$logfile 2>&1
    echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc" >> /etc/ssh/sshd_config 
    sed -i '/^PrintLastLog.*$/d' /etc/ssh/sshd_config >>$logfile 2>&1
    echo "PrintLastLog yes" >> /etc/ssh/sshd_config 
    sed -i '/^Banner.*$/d' /etc/ssh/sshd_config >>$logfile 2>&1
    echo "Banner /etc/issue" >> /etc/ssh/sshd_config 
  fi

echo 65
  

  #install cronie
  yum -y install cronie >>$logfile 2>&1

echo 70

  #enable aide filesystem auditing
  if [ $enable_aide -eq 1 ];then
    yum -y install cron aide >>$logfile 2>&1
    #default aide config being used, may wish to customize

    #background aid database initialization
    nice aide -i >>$logfile 2>&1&
    #add aide to crontab
    if [ -e /etc/crontab ];then
      if [ `grep -c aide /etc/crontab` -lt 1 ];then 
        echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
      fi
    else
        echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
    fi
  fi

echo 75

  #install screen
  yum -y install screen >>$logfile 2>&1

  #disable root login from virtual consoles and serial ports
  sed -i '/^vc.*$/d' /etc/securetty >>$logfile 2>&1
  sed -i '/^ttyS.*$/d' /etc/securetty >>$logfile 2>&1

  #disable null passwords
  sed -i 's/nullok//g' /etc/pam.d/system-auth >>$logfile 2>&1
  sed -i 's/nullok//g' /etc/pam.d/system-auth-ac >>$logfile 2>&1

echo 80

  #set password requirements
  sed -i 's/^PASS_MIN_LEN.*$/PASS_MIN_LEN 14/g' /etc/login.defs >>$logfile 2>&1
  sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 1/g' /etc/login.defs >>$logfile 2>&1
  sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 60/g' /etc/login.defs >>$logfile 2>&1
  sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/g' /etc/login.defs >>$logfile 2>&1
  #minimum digits in password
  if [ `grep -c dcredit /etc/pam.d/system-auth` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 dcredit=-1/g" /etc/pam.d/system-auth >>$logfile 2>&1
  fi
  #minimum uppercase characters
  if [ `grep -c ucredit /etc/pam.d/system-auth` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 ucredit=-1/g" /etc/pam.d/system-auth >>$logfile 2>&1
  fi
  #minimum special characters
  if [ `grep -c ocredit /etc/pam.d/system-auth` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 ocredit=-1/g" /etc/pam.d/system-auth >>$logfile 2>&1
  fi
  #minimum lowercase characters
  if [ `grep -c lcredit /etc/pam.d/system-auth` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 lcredit=-1/g" /etc/pam.d/system-auth >>$logfile 2>&1
  fi
  #different characters between changes
  if [ `grep -c difok /etc/pam.d/system-auth` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 difok=4/g" /etc/pam.d/system-auth >>$logfile 2>&1
  fi
  #remember past passwords so that they cannot be reused
  if [ `grep pam_unix /etc/pam.d/system-auth| grep -c 'remember='` -lt 1 ];then
    sed -ie "s/\(^password.*pam_unix.so.*\)/\1 remember=24/g" /etc/pam.d/system-auth >>$logfile 2>&1
  fi 
  #remember past passwords so that they cannot be reused
  if [ `grep pam_unix /etc/pam.d/system-auth| grep -c 'maxrepeat='` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 maxrepeat=3/g" /etc/pam.d/system-auth >>$logfile 2>&1
  fi 
echo 85
  #set inactive user account to 35 days
  sed -i 's/^INACTIVE=.*/INACTIVE=35/g' /etc/default/useradd >>$logfile 2>&1

  #lock account on 3 failed attempts
  if [ `grep -c pam_faillock /etc/pam.d/system-auth-ac` -lt 1 ];then
    sed -ie "s/\(^auth.*required.*pam_env.so\)/\1\nauth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900\nauth required pam_faillock.so authsucc deny=3 unlock_time=604800 fail_interval=900\n/g" /etc/pam.d/system-auth-ac  >>$logfile 2>&1
  fi

  #disable passwordless single user mode
  sed -i 's/^SINGLE=.*$/SINGLE=\/sbin\/sulogin/g' /etc/sysconfig/init  >>$logfile 2>&1

  #disable interactive boot
  sed -i 's/^PROMPT=.*$/PROMPT=no/g' /etc/sysconfig/init >>$logfile 2>&1

  #fix umask 
  sed -i 's/.*umask 0.*/umask 077/g' /etc/bashrc >>$logfile 2>&1
  sed -i 's/.*umask 0.*/umask 077/g' /etc/csh.cshrc >>$logfile 2>&1
  sed -i 's/.*umask 0.*/umask 077/g' /etc/profile >>$logfile 2>&1
  sed -i 's/.*umask 0.*/umask 077/g' /etc/login.defs >>$logfile 2>&1

  #do not send icmpv4 redirects
  sysctl -w net.ipv4.conf.default.send_redirects=0 >>$logfile 2>&1
  sed -i '/$net.ipv4.conf.default.send_redirects.*$/d' /etc/sysctl.conf  >>$logfile 2>&1
  echo "net.ipv4.conf.default.send_redirects = 0">>/etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.send_redirects=0 >>$logfile 2>&1
  sed -i '/$net.ipv4.conf.all.send_redirects.*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv4.conf.all.send_redirects = 0">>/etc/sysctl.conf
  
  #kernel settings
  sysctl -w kernel.exec-shield=1 >>$logfile 2>&1
  sed -i '/$kernel.exec-shield*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "kernel.exec-shield = 1">>/etc/sysctl.conf
  sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 >>$logfile 2>&1
  sed -i '/$net.ipv4.icmp_ignore_bogus_error_responses*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv4.icmp_ignore_bogus_error_responses = 1">>/etc/sysctl.conf

  #do not accept icmpv4 redirects
  sysctl -w net.ipv4.conf.default.accept_redirects=0 >>$logfile 2>&1
  sed -i '/$net.ipv4.conf.default.accept_redirects.*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv4.conf.default.accept_redirects = 0">>/etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.accept_redirects=0 >>$logfile 2>&1
  sed -i '/$net.ipv4.conf.all.accept_redirects.*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv4.conf.all.accept_redirects = 0">>/etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.secure_redirects=0 >>$logfile 2>&1
  sed -i '/$net.ipv4.conf.all.secure_redirects.*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv4.conf.all.secure_redirects = 0">>/etc/sysctl.conf
  sysctl -w net.ipv4.conf.default.secure_redirects=0 >>$logfile 2>&1
  sed -i '/$net.ipv4.conf.default.secure_redirects.*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv4.conf.default.secure_redirects = 0">>/etc/sysctl.conf

  #log martians
  sysctl -w net.ipv4.conf.all.log_martians=1 >>$logfile 2>&1
  sed -i '/$net.ipv4.conf.all.log_martians.*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv4.conf.all.log_martians = 1">>/etc/sysctl.conf

  #reverse path filter
  sysctl -w net.ipv4.conf.all.rp_filter=1 >>$logfile 2>&1
  sed -i '/$net.ipv4.conf.all.rp_filter.*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv4.conf.all.rp_filter = 1">>/etc/sysctl.conf

  #disable routing
  sysctl -w net.ipv4.ip_forward=0 >>$logfile 2>&1
  sed -i '/$net.ipv4.ip_forward.*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv4.ip_forward = 0">>/etc/sysctl.conf
  
  #do not accept source routed packets
  sysctl -w net.ipv4.conf.all.accept_source_route=0 >>$logfile 2>&1
  sed -i '/$net.ipv4.conf.all.accept_source_route.*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv4.conf.all.accept_source_route = 0">>/etc/sysctl.conf

  #ignore ipv6 redirects
  sysctl -w net.ipv6.conf.default.accept_redirects=0 >>$logfile 2>&1
  sed -i '/$net.ipv6.conf.default.accept_redirects.*$/d' /etc/sysctl.conf >>$logfile 2>&1
  echo "net.ipv6.conf.default.accept_redirects = 0">>/etc/sysctl.conf

echo 90

  #disable ipv6
  echo "options ipv6 disable=1" > /etc/modprobe.d/disable_ipv6.conf

  #disable datagram congestion control protocol
  echo "install dccp /bin/true" > /etc/modprobe.d/disable_dccp.conf

  #disable sctp
  echo "install sctp /bin/true" > /etc/modprobe.d/disable_sctp.conf

  #disable rds
  echo "install rds /bin/true" > /etc/modprobe.d/disable_rds.conf

  #disable tipc
  echo "install tipc /bin/true" > /etc/modprobe.d/disable_tipc.conf

  #disable bluetooth
  echo "install net-pf-31 /bin/true
install bluetooth /bin/true" > /etc/modprobe.d/disable_bluetooth.conf

  #disable usb storage
  echo "install usb-storage /bin/true" > /etc/modprobe.d/disable_usb_storage.conf


  #fix syslog permissions
  chmod -f 0600 /var/log/* >>$logfile 2>&1
  find -O1 /var/log -type d |xargs -r chmod -f 0700 >>$logfile 2>&1
  chmod -f 755 /var/log >>$logfile 2>&1

  #remove privileged accounts
  userdel shutdown >>$logfile 2>&1
  userdel reboot >>$logfile 2>&1
  userdel halt >>$logfile 2>&1

  #fix permissions
  chmod -f 0640 /etc/security/access.conf >>$logfile 2>&1
  setfacl --remove-all /etc/security/access.conf  >>$logfile 2>&1
  chmod -f 0600 /etc/sysctl.conf  >>$logfile 2>&1
  setfacl --remove-all /etc/sysctl.conf >>$logfile 2>&1
  chmod -f 0600 -R /etc/ssh >>$logfile 2>&1
  chmod -f a+rx /bin/* >>$logfile 2>&1
  chmod -f a+rx /sbin/* >>$logfile 2>&1
  chmod -f a+rx /usr/local/* >>$logfile 2>&1


  #disable core dumps
  if [ `grep ^.*hard.*core.*0 /etc/security/limits.conf -c` -ne 1 ];then echo "* hard core 0">> /etc/security/limits.conf; fi

  #set max logins
  if [ `grep ^.*hard.*maxlogins.* /etc/security/limits.conf -c` -ne 1 ];then echo "* hard maxlogins 10">> /etc/security/limits.conf; fi 

  #fix ctrl-alt-delete behavior in inittab 
  sed -i 's/^exec \/sbin.*/exec \/usr\/bin\/logger -p security.info "Control-Alt-Delete pressed"/g' /etc/init/control-alt-delete.conf >>$logfile 2>&1

  #remove unauthorized console permissions
  if [ -e /etc/security/console.perms ];then
    rm /etc/security/console.perms >>$logfile 2>&1
  fi
  sed -i '/.*pam_console.so.*/ s/^/#/' /etc/pam.d/* >>$logfile 2>&1

  #enable auditing at boot time in grub config
  if [ -e /boot/grub/menu.lst ];then
    if [ `grep -c 'audit=1' /boot/grub/menu.lst` -lt 1 ];then
      sed -i '/.*kernel \// s/$/ audit=1/' /boot/grub/menu.lst >>$logfile 2>&1
    fi
  fi
  if [ -e /etc/grub.conf ];then
    if [ `grep -c 'audit=1' /boot/grub/menu.lst` -lt 1 ];then
      sed -i '/.*kernel \// s/$/ audit=1/' /etc/grub.conf >>$logfile 2>&1
    fi
  fi

echo 90

  #clamav
  if [ $enable_clamav -eq 1 ];then
    yum -y install clamav clamd >>$logfile 2>&1

echo 93

    chmod -f 0744 /var/log/clamav/ -R
    chown clamav:clamav /var/clamav/* >>$logfile 2>&1
  
    #run freshclam if you wish to update virus definitions - we'll background it as it can take a while
    (freshclam >>$logfile 2>&1
    if [ `which setsebool >/dev/null 2>&1` ];then
      setsebool -P clamd_use_jit on
    fi 
    #sed -i 's/^LogFile.*/LogFile \/var\/log\/clamav\/clamav\.log/g' /etc/clamd.conf >>$logfile 2>&1
    chkconfig clamd on >>$logfile 2>&1
    /etc/init.d/clamd start >>$logfile 2>&1)>>$logfile 2>&1 &
    disown
  
  fi

echo 97


  #robots.txt
  if [ -e /var/www/robots.txt ];then
    cp /var/www/robots.txt /var/www/robots.txt.bak >>$logfile 2>&1
    echo "User-agent: *
Disallow: /" > /var/www/robots.txt
  fi

  #fix mysql permissions  
  if [ -d /var/lib/mysql ];then
    chmod -f ug+rwx /var/lib/mysql/* -R >>$logfile 2>&1
  fi

  #remove repositories
  mkdir -p /etc/yum.repos.d.stig_backup >>$logfile 2>&1
  mv -f /etc/yum.repos.d/* /etc/yum.repos.d.stig_backup/. >>$logfile 2>&1
  #let's make sure cron has started
  service crond start >>$logfile 2>&1

echo 98

  #restart audit
  /etc/init.d/auditd restart >>$logfile 2>&1

echo 100;sleep 1

} #end stig function

function check_repos {
  echo 5
  sleep 1

  check_el_version

  echo 10

  #restore old repos if we've run this before
  if [ -d /etc/yum.repos.d.stig_backup ];then
    cp -a /etc/yum.repos.d.stig_backup/* /etc/yum.repos.d/. >>$logfile 2>&1
  fi
  echo 20
  yum clean all >>$logfile 2>&1
  echo 30
  if [ `yum repolist 2>&1|tail -n1|grep -c '[1-9]'` -lt 1 ];then
    echo "There appear to be no repositories enabled, please fix this before continuing with STIGification, exiting." > $errorlog
    exit 3 
  fi

  echo 100;sleep 1

} #end check_repos function



#run
check_repos|$progress --gauge "Initializing STIGification script..." 10 70 0;catch_error
stig|$progress --gauge "STIGifying system... " 10 70 0;catch_error
$progress --msgbox "STIGification complete.  A logfile of the process is location at ${logfile}." 10 70 0

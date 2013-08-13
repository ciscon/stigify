#!/bin/bash
# STIG enforcement script [EL6]
# 8-13-13

echo 0

  #backup pam.d
  cp -a /etc/pam.d /etc/pam.d_stig_backup

  #remove compilers
  yum -y erase gcc gcc-c++

echo 5

  #remove x-windows?  this is a good idea, but there may be a valid reason for it to exist.
  #yum -y erase xorg-x11-server-common

  #disable listening on 25, even on localhost
  if [ -e /etc/postfix/master.cf ];then

    sed -ie "s/\(^smtp.*inet.*\)/\#\1/g" /etc/postfix/master.cf
    /etc/init.d/postfix restart >/dev/null 2>&1

  fi

echo 10

  #remove java source files
  find /var/www/ -name *.java -exec rm {} \;
 
  #enable ntpd
  yum -y install ntp.x86_64
  chkconfig ntpd on

  #enable auditd
  chkconfig auditd on

echo 15

  #change audit behavior to send email
  sed -i 's/^space_left_action.*/space_left_action = EMAIL/g' /etc/audit/auditd.conf
  #switch to single user mode when audit space too low
  sed -i 's/^disk_full_action.*/disk_full_action = SINGLE/g' /etc/audit/auditd.conf
  #switch to single user mode when audit space too low
  sed -i 's/^admin_space_left_action.*/admin_space_left_action = SINGLE/g' /etc/audit/auditd.conf
  #switch to single user mode when disk error occurs 
  sed -i 's/^disk_error_action.*/disk_error_action = SINGLE/g' /etc/audit/auditd.conf
  #audit call adjtimex/timeofday
  if [ `grep -c -e '-a always,exit -F arch=b64 -S settimeofday -S adjtimex -S clock_settime -k audit_time_rules' /etc/audit/audit.rules` -eq 0 ];then
    echo "-a always,exit -F arch=b64 -S settimeofday -S adjtimex -S clock_settime -k audit_time_rules" >> /etc/audit/audit.rules
  fi
echo 20
#start auditd for auditctl to work
/etc/init.d/auditd start >/dev/null 2>&1
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
  #audit network
  if [ `auditctl -l | egrep '(/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)'` -eq 0 ];then
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
  sed -i 's/.*active.*/active = yes/g' /etc/audisp/plugins.d/syslog.conf
echo 40
  

  #remove services
  yum -y erase xinetd
  yum -y erase telnet-server
  yum -y erase rsh-server
  yum -y erase ypserv
  yum -y erase tftp-server

echo 50

  #disable services
  chkconfig rexec off
  chkconfig rlogin off 
  chkconfig ypbind off
  chkconfig avahi-daemon off
  chkconfig abrtd off
  chkconfig atd off
  chkconfig --level 0123456 autofs off
  service autofs stop
  chkconfig ntpdate off
  chkconfig oddjobd off
  chkconfig qpidd off
  chkconfig rdisc off
  chkconfig netconsole off
  chkconfig bluetooth off
  service bluetooth stop

echo 60

  #set default runlevel to 3
  sed -i 's/^id.*initdefault.*/id:3:initdefault:/g' /etc/inittab

  #ssh daemon settings
  if [ -e /etc/ssh/sshd_config ];then
    sed -i '/^ClientAliveInterval.*$/d' /etc/ssh/sshd_config
    echo "ClientAliveInterval 900" >> /etc/ssh/sshd_config
    sed -i '/^ClientAliveCountMax.*$/d' /etc/ssh/sshd_config
    echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
    sed -i '/^IgnoreRhosts.*$/d' /etc/ssh/sshd_config
    echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
    sed -i '/^HostbasedAuthentication.*$/d' /etc/ssh/sshd_config
    echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
    sed -i '/^PermitRootLogin.*$/d' /etc/ssh/sshd_config
    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    sed -i '/^PermitEmptyPasswords.*$/d' /etc/ssh/sshd_config
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
    sed -i '/^PermitUserEnvironment.*$/d' /etc/ssh/sshd_config
    echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
    sed -i '/^Ciphers.*$/d' /etc/ssh/sshd_config
    echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc" >> /etc/ssh/sshd_config
    sed -i '/^PrintLastLog.*$/d' /etc/ssh/sshd_config
    echo "PrintLastLog yes" >> /etc/ssh/sshd_config
    sed -i '/^Banner.*$/d' /etc/ssh/sshd_config
    echo "Banner /etc/issue" >> /etc/ssh/sshd_config
  fi

echo 65
  

  #enable aide filesystem auditing
  yum -y install aide
  #default aide config being used, may wish to customize

  #background aid database initialization
  nice aid -i&
  #add aide to crontab
  if [ `grep -c aide /etc/crontab` -lt 1 ];then
    echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
  fi

echo 75

  #install screen
  yum -y install screen

  #disable root login from virtual consoles and serial ports
  sed -i '/^vc.*$/d' /etc/securetty
  sed -i '/^ttyS.*$/d' /etc/securetty

  #disable null passwords
  sed -i 's/nullok//g' /etc/pam.d/system-auth
  sed -i 's/nullok//g' /etc/pam.d/system-auth-ac

echo 80

  #set password requirements
  sed -i 's/^PASS_MIN_LEN.*$/PASS_MIN_LEN 14/g' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 1/g' /etc/login.defs
  sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 60/g' /etc/login.defs
  sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/g' /etc/login.defs
  #minimum digits in password
  if [ `grep -c dcredit /etc/pam.d/system-auth` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 dcredit=-1/g" /etc/pam.d/system-auth
  fi
  #minimum uppercase characters
  if [ `grep -c ucredit /etc/pam.d/system-auth` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 ucredit=-1/g" /etc/pam.d/system-auth
  fi
  #minimum special characters
  if [ `grep -c ocredit /etc/pam.d/system-auth` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 ocredit=-1/g" /etc/pam.d/system-auth
  fi
  #minimum lowercase characters
  if [ `grep -c lcredit /etc/pam.d/system-auth` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 lcredit=-1/g" /etc/pam.d/system-auth
  fi
  #different characters between changes
  if [ `grep -c difok /etc/pam.d/system-auth` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 difok=4/g" /etc/pam.d/system-auth
  fi
  #remember past passwords so that they cannot be reused
  if [ `grep pam_unix /etc/pam.d/system-auth| grep -c 'remember='` -lt 1 ];then
    sed -ie "s/\(^password.*pam_unix.so.*\)/\1 remember=24/g" /etc/pam.d/system-auth
  fi 
  #remember past passwords so that they cannot be reused
  if [ `grep pam_unix /etc/pam.d/system-auth| grep -c 'maxrepeat='` -lt 1 ];then
    sed -ie "s/\(^password.*pam_cracklib.so.*\)/\1 maxrepeat=3/g" /etc/pam.d/system-auth
  fi 
echo 85
  #set inactive user account to 35 days
  sed -i 's/^INACTIVE=.*/INACTIVE=35/g' /etc/default/useradd

  #lock account on 3 failed attempts
  if [ `grep -c pam_faillock /etc/pam.d/system-auth-ac` -lt 1 ];then
    sed -ie "s/\(^auth.*required.*pam_env.so\)/\1\nauth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900\nauth required pam_faillock.so authsucc deny=3 unlock_time=604800 fail_interval=900\n/g" /etc/pam.d/system-auth-ac 
  fi

  #disable passwordless single user mode
  sed -i 's/^SINGLE=.*$/SINGLE=\/sbin\/sulogin/g' /etc/sysconfig/init 

  #disable interactive boot
  sed -i 's/^PROMPT=.*$/PROMPT=no/g' /etc/sysconfig/init

  #fix umask 
  sed -i 's/.*umask 0.*/umask 077/g' /etc/bashrc
  sed -i 's/.*umask 0.*/umask 077/g' /etc/csh.cshrc
  sed -i 's/.*umask 0.*/umask 077/g' /etc/profile
  sed -i 's/.*umask 0.*/umask 077/g' /etc/login.defs

  #do not send icmpv4 redirects
  sysctl -w net.ipv4.conf.default.send_redirects=0
  sed -i '/$net.ipv4.conf.default.send_redirects.*$/d' /etc/sysctl.conf 
  echo "net.ipv4.conf.default.send_redirects = 0">>/etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.send_redirects=0
  sed -i '/$net.ipv4.conf.all.send_redirects.*$/d' /etc/sysctl.conf
  echo "net.ipv4.conf.all.send_redirects = 0">>/etc/sysctl.conf

  #do not accept icmpv4 redirects
  sysctl -w net.ipv4.conf.default.accept_redirects=0
  sed -i '/$net.ipv4.conf.default.accept_redirects.*$/d' /etc/sysctl.conf
  echo "net.ipv4.conf.default.accept_redirects = 0">>/etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.accept_redirects=0
  sed -i '/$net.ipv4.conf.all.accept_redirects.*$/d' /etc/sysctl.conf
  echo "net.ipv4.conf.all.accept_redirects = 0">>/etc/sysctl.conf
  sysctl -w net.ipv4.conf.all.secure_redirects=0
  sed -i '/$net.ipv4.conf.all.secure_redirects.*$/d' /etc/sysctl.conf
  echo "net.ipv4.conf.all.secure_redirects = 0">>/etc/sysctl.conf
  sysctl -w net.ipv4.conf.default.secure_redirects=0
  sed -i '/$net.ipv4.conf.default.secure_redirects.*$/d' /etc/sysctl.conf
  echo "net.ipv4.conf.default.secure_redirects = 0">>/etc/sysctl.conf

  #log martians
  sysctl -w net.ipv4.conf.all.log_martians=1
  sed -i '/$net.ipv4.conf.all.log_martians.*$/d' /etc/sysctl.conf
  echo "net.ipv4.conf.all.log_martians = 1">>/etc/sysctl.conf

  #reverse path filter
  sysctl -w net.ipv4.conf.all.rp_filter=1
  sed -i '/$net.ipv4.conf.all.rp_filter.*$/d' /etc/sysctl.conf
  echo "net.ipv4.conf.all.rp_filter = 1">>/etc/sysctl.conf

  #disable routing
  sysctl -w net.ipv4.ip_forward=0
  sed -i '/$net.ipv4.ip_forward.*$/d' /etc/sysctl.conf
  echo "net.ipv4.ip_forward = 0">>/etc/sysctl.conf
  
  #do not accept source routed packets
  sysctl -w net.ipv4.conf.all.accept_source_route=0
  sed -i '/$net.ipv4.conf.all.accept_source_route.*$/d' /etc/sysctl.conf
  echo "net.ipv4.conf.all.accept_source_route = 0">>/etc/sysctl.conf

  #ignore ipv6 redirects
  sysctl -w net.ipv6.conf.default.accept_redirects=0
  sed -i '/$net.ipv6.conf.default.accept_redirects.*$/d' /etc/sysctl.conf
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
  chmod 0600 /var/log/*

  #remove privileged accounts
  userdel shutdown
  userdel reboot
  userdel halt

  #fix permissions
  chmod  0640 /etc/security/access.conf
  setfacl --remove-all /etc/security/access.conf 
  chmod  0600 /etc/sysctl.conf 
  setfacl --remove-all /etc/sysctl.conf
  chmod 0600 -R /etc/ssh
  chmod a+rx /bin/*
  chmod a+rx /sbin/*
  chmod a+rx /usr/local/*


  #disable core dumps
  if [ `grep ^.*hard.*core.*0 /etc/security/limits.conf -c` -ne 1 ];then echo "* hard core 0">> /etc/security/limits.conf; fi

  #set max logins
  if [ `grep ^.*hard.*maxlogins.* /etc/security/limits.conf -c` -ne 1 ];then echo "* hard maxlogins 10">> /etc/security/limits.conf; fi 

  #fix ctrl-alt-delete behavior in inittab 
  sed -i 's/^exec \/sbin.*/exec \/usr\/bin\/logger -p security.info "Control-Alt-Delete pressed"/g' /etc/init/control-alt-delete.conf
  #this is only for rhel5
  #sed -i 's/^ca::ctrlaltdel:\/sbin\/shutdown -t3 -r now$/ca:nil:ctrlaltdel:\/usr\/bin\/logger -p security.info "Ctrl-Alt-Del was pressed"/g' /etc/inittab

  #remove unauthorized console permissions
  rm /etc/security/console.perms
  sed -i '/.*pam_console.so.*/ s/^/#/' /etc/pam.d/*

  #enable auditing at boot time in grub config
  if [ -e /boot/grub/menu.lst ];then
    if [ `grep -c 'audit=1' /boot/grub/menu.lst` -lt 1 ];then
      sed -i '/.*kernel \// s/$/ audit=1/' /boot/grub/menu.lst
    fi
  fi
  if [ -e /etc/grub.conf ];then
    if [ `grep -c 'audit=1' /boot/grub/menu.lst` -lt 1 ];then
      sed -i '/.*kernel \// s/$/ audit=1/' /etc/grub.conf
    fi
  fi

echo 90

  #clamav
  yum -y install clamav clamd
  #run freshclam if you wish to update virus definitions
  chown clamav:clamav /var/clamav/*
  chkconfig clamd on
  /etc/init.d/clamd start
echo 95
  #robots.txt
  if [ -e /var/www/robots.txt ];then
    cp /var/www/robots.txt /var/www/robots.txt.bak
    echo "User-agent: *
Disallow: /" > /var/www/robots.txt
  fi

  #fix mysql permissions  
  if [ -d /var/lib/mysql ];then
    chmod ug+rwx /var/lib/mysql/* -R
  fi

  #remove repositories
  mkdir -p /etc/yum.repos.d.stig_backup
  mv /etc/yum.repos.d/* /etc/yum.repos.d.stig_backup/.
  #let's make sure cron has started
  service crond start

  #restart audit
  /etc/init.d/auditd restart

echo 100;sleep 1

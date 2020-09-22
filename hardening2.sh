#!/bin/bash
#
# Perform basic hardening for Debian distributions

#Check if running with proper privileges
function check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script requires root privileges." 1>&2
    exit 1
  fi
}

#  System update and upgrade
sys_upgrades() {
    echo -e "\n-------------------------\nSystem Upgrade\n-------------------------\n"
    apt-get --yes update
    apt-get --yes upgrade
    apt-get --yes autoremove
    apt-get --yes autoclean
}

#  Setting-up sudo e lock root account
set_sudo() {
    echo -e "\n-------------------------\nInstall sudo\n-------------------------\n"
    apt-get --yes install sudo
}


disable_root() {
    echo -e "\n-------------------------\nLock root account\n-------------------------\n"
    passwd -l root
}

# Remove  the standard network file sharing
purge_nfs() {
    echo -e "\n-------------------------\nRemove Network File Sharing\n-------------------------\n"
    apt-get --yes purge nfs-kernel-server nfs-common portmap rpcbind autofs
}

#  Setting up firewall without loose remote connection and harden ssh against brute force attack
firewall() {
    echo -e "\n-------------------------\nSetting up Firewall\n-------------------------\n\n\n-------------------------\nWARNING all connection except ssh will be closed by default\n"
    apt-get --yes install ufw
    ufw default allow
    ufw --force enable
    ufw allow 22/tcp
    ufw default deny
    ufw status numbered
    }

harden_ssh_brute() {
    echo -e "\n-------------------------\nLimit connection from the same IP\n-------------------------\n"    
    # This will only allow 6 connections every 30 seconds from the same IP address.
    ufw limit OpenSSH
}

#  disable network discovery and MTA service
disable_avahi() {
    echo -e "\n-------------------------\nDisable Avahi\n-------------------------\n"
    update-rc.d -f avahi-daemon disable
}

disable_exim_pckgs() {
    echo -e "\n-------------------------\nDisable exim4\n-------------------------\n"
    update-rc.d -f exim4 disable
    }

#  enabling activity logs
process_accounting() {
    echo -e "\n-------------------------\nSetting up process accounting to keep tracks of commands previously run by users\n-------------------------\n"
    apt-get --yes  install acct
}

#  enabling unattended updates
unattended_upg() {
      apt-get --yes install unattended-upgrades
      dpkg-reconfigure -plow unattended-upgrades
}

# disable c and c++ compilers
disable_compilers() {
    echo -e "\n-------------------------\nDisable c and c+ compiler\n-------------------------\n"
    
FILE=/usr/bin/cc
if test -f "$FILE"; then
    chmod 000 /usr/bin/cc; else
        echo "$FILE don't extists."
fi

FILE=/usr/bin/gcc
if test -f "$FILE"; then
    chmod 000 /usr/bin/gcc; else
        echo "$FILE don't extists."
fi

}

# start with kernel tuning
kernel_tuning() {
    echo -e "\n-------------------------\nStart kernel tuning\n-------------------------\n"  
    sh -c 'echo "kernel.randomize_va_space=1" >> /etc/sysctl.conf'
    echo -e "\nEnable IP spoofing protection"
    sh -c 'echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf'
    echo -e "\nDisable IP source routing"
    sh -c 'echo "net.ipv4.conf.all.accept_source_route=0" >> /etc/sysctl.conf'
    echo -e "\nIgnoring broadcasts request"
    sh -c 'echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf'
    echo -e "\nMake sure spoofed packets get logged"
    sh -c 'echo "net.ipv4.conf.all.log_martians=1" >> /etc/sysctl.conf'
    sh -c 'echo "net.ipv4.conf.default.log_martians=1" >> /etc/sysctl.conf'
    echo -e "\nDisable ICMP routing redirects"
    sh -c 'echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf'
    sh -c 'echo "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.conf'
    sh -c 'echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.conf'
    echo -e "\nDisables the magic-sysrq key"
    sh -c 'echo "kernel.sysrq=0" >> /etc/sysctl.conf'
    echo -e "\nTurn off the tcp_timestamps"
    sh -c 'echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.conf'
    echo -e "\nEnable TCP SYN Cookie Protection"
    sh -c 'echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf'
    echo -e "\nEnable bad error message Protection"
    sh -c 'echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.conf'
    echo -e "\nRELOAD WITH NEW SETTINGS"
    /sbin/sysctl -p
}


#  Start with SSH tuning
echo -e "\n-------------------------\nStart SSH tuning\n-------------------------\n"


SSHD_CONF_LOC="/etc/ssh/sshd_config"

#Back up sshd_config to current directory
function backup_sshd_config() {
  cp $SSHD_CONF_LOC .
  echo "Backed up sshd_config to $(pwd)"
}

#Change SSH protocol to 2
function change_protocol() {
  sed -i -e 's/^.*Protocol.*$/Protocol 2/' $SSHD_CONF_LOC
  echo "Set protocol 2"
}

#Change PermitRootLogin to no
function root_login() {
  sed -i -e 's/^.*PermitRootLogin.*$/PermitRootLogin no/' $SSHD_CONF_LOC
  echo "No root login"
}

#Change max authentication attempts to 3
function max_auth() {
  sed -i -e "s/^.*MaxAuthTries.*$/MaxAuthTries 3/" $SSHD_CONF_LOC
  echo "Max auth tries set to 3"
}

#Disallow empty passwords
function empty_passwords() {
  sed -i -e 's/^.*PermitEmptyPasswords.*$/PermitEmptyPasswords no/' $SSHD_CONF_LOC
  echo "No empty password"
}

#Change login gracetime to 60 sec
function login_gt() {
  sed -i -e "s/^.*LoginGraceTime.*$/LoginGraceTime 60/" $SSHD_CONF_LOC
  echo "Gracetime set too 1 minute"
}

#Disable rhosts
function disable_rhosts() {
  sed -i -e 's/^.*IgnoreRhosts.*$/IgnoreRhosts yes/' $SSHD_CONF_LOC
  echo "Ignore rhost"
}

#Set warning banner
function warning_banner() {
  touch /etc/ssh/sshd_banner
  cat >/etc/ssh/sshd_banner <<EOF
   WARNING : Unauthorized access to this system is forbidden and will be
   prosecuted by law. By accessing this system, you agree that your actions
   may be monitored if unauthorized usage is suspected.
EOF
sed -i -e 's=^.*Banner.*$=Banner /etc/ssh/sshd_banner=' $SSHD_CONF_LOC
 echo "Set Warning Banner"
}


main() {
    check_root
    sys_upgrades
    purge_nfs
    firewall
    harden_ssh_brute
    unattended_upg
    disable_avahi
    disable_exim_pckgs
    process_accounting
    disable_compilers
    kernel_tuning
    backup_sshd_config
    change_protocol
    root_login
    max_auth
    empty_passwords
    login_gt
    disable_rhosts
    warning_banner
    set_sudo
    disable_root
    clear
    echo -e "CONGRATULATION!\nYour system is hardened\nDon't forget to restart sshd!"
}

main "$@"

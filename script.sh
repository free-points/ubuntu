#!/bin/bash

# Checks for root
if [[ $EUID -ne 0 ]]; then
    echo "This script requires root privileges. Please type 'sudo !!' or login as root using 'su'."
    exit 1
else echo "Confirmed running as root."
fi

# Initialize some variables.
export buck=0
export bum=0
fstab=$(grep -c "tmpfs" /etc/fstab)

# Update the package cache
apt-get -y update

# Install Programs
echo "Install the supplementary programs Graphical Firewall Management, Check Rootkit, rkhunter, and Boot-up Manager?"
echo -n "(if already installed press y)"
read -r -p "$* [y/n]: " sup
case $sup in
    [Yy]* ) apt-get -y install gufw bum rkhunter chkrootkit && export bum=1 ;;
    [Nn]* ) echo "Your choice is noted." && export bum=0 ;;
    * ) echo "Invalid input! Please answer y (yes) or n (no)."
esac


# Git buck security
echo -n "Clone into davewood's buck-security?"
read -r -p "$* [y/n]: " gbk
case $gbk in
    [Yy]* ) git clone https://github.com/davewood/buck-security && export buck=1 ;;
    [Nn]* ) echo "Your choice is noted." && export buck=0 ;;
    * ) echo "Invalid input! Please answer y (yes) or n (no)."
esac

# Firewall
ufw enable
ufw deny 23
ufw deny 111
ufw deny 515
ufw deny 2049
ufw deny 5900

# Remove Samba (If Installed)
echo -n "Would you like to remove SAMBA?"
read -r -p "$* [y/n]: " smb
case $smb in
    [Yy]* ) apt-get purge samba && ufw deny 139,445/tcp ;;
    [Nn]* ) echo "Moving on..." ;;
    * ) echo "Invalid input! Please answer y (yes) or n (no)."
esac

# Add PPA for Mozilla Firefox; <s>Add PPA for Libre Office</s>
add-apt-repository ppa:ubuntu-mozilla-security/ppa # && add-apt-repository ppa:libreoffice/ppa

# Update local package cache
apt-get update

echo "Perform software upgrades? Note that this step may take a while,"
echo "and will tie up the apt package management."
# while true; do
read -r -p "$* [y/n]: " yn
case $yn in
    [Yy]* ) apt-get upgrade ;;
    [Nn]* ) echo "Understood. Please remember to run 'apt-get upgrade' later." ;;
    * ) echo "Invalid input! Please answer y (yes) or n (no)."
esac

# Turns off Guest ACCT
echo -n "Is your Ubuntu version below 16?"
read -r -p "$* [y/n]: " yn
case $yn in
    [Yy]* ) sh -c 'printf "[SeatDefaults]\nallow-guest=false\n" > /etc/lightdm/lightdm.conf' ;;
    [Nn]* ) sh -c 'printf "[SeatDefaults]\nallow-guest=false\n" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf' ;;
    * ) echo "Invalid input! Please answer y (yes) or n (no)."
esac

# Password Age Limits
sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10'  /etc/login.defs
sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs

# Password Auth
sed -i '1 s/^/auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent\n/' /etc/pam.d/common-auth

# Makes strong password
apt-get -y install libpam-cracklib
sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\n/' /etc/pam.d/common-password

# Cracking tools/malware.  You get the drift.
apt-get -y remove hydra* ophcrack* john* nikto* netcat* aircrack-ng* hashcat* nmap* ncrack* wireshark*

# Enables daily updates
sed -i -e 's/APT::Periodic::Update-Package-Lists.*\+/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/10periodic
sed -i -e 's/APT::Periodic::Download-Upgradeable-Packages.*\+/APT::Periodic::Download-Upgradeable-Packages "0";/' /etc/apt/apt.conf.d/10periodic

# Security Updates
if grep -qF "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted" /etc/apt/sources.list
then
    echo "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted" >> /etc/apt/sources.list
fi

echo "###Automatic updates###"
cat /etc/apt/apt.conf.d/10periodic
echo ""
echo "###Important Security Updates###"
cat /etc/apt/sources.list

# Disable Root Login (SSHd.CONF)
if [[ -f /etc/ssh/sshd_config ]]; then
    sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
    echo "Disabled SSH root login."
else
    echo "NO SSH SERVER DETECTED, PLEASE LOOK AT README!"
    sleep 5s
fi

# Start the services manager (Boot Up Manager)
if [[ $bum == 1 ]]; then
    echo -n "Would you like to start BUM(Boot Up Manager)? "
    # while true; do
    read -r -p "$* [y/n]: " yn
    case $yn in
        [Yy]* ) bum ;;
        [Nn]* ) echo "Okay, moving on..." ;;
        * ) echo "Invalid input! Please answer y (yes) or n (no)."
    esac
else
    echo "Boot-up manager not installed, so not running."
fi

# Change Root Login
echo "Would you like to (c)hange the root password, (d)isable the account, or (s)kip this step?"
# while true; do
read -r -p "$* [c/d/s]: " cds
case $cds in
    [Dd]* ) passwd -d root ;;
    [Ss]* ) echo "Alrighty, moving on..." ;;
    [Cc]* ) passwd root ;;
    * ) echo "Invalid input! Please answer c (change), d (disable), or s (skip)."
esac

echo -n "Would you like to change all \"human\" account passwords?"
cngpass() {
    echo "Tip! Copy Cyb3RP@tr!0t$ into gedit, press enter, Ctrl+A then Ctrl+C. Use the middle mouse"
    echo "button or Shift+Insert to quickly paste the password into the terminal. Write it down!"
    for i in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
        echo Changing password for user "$i";
        passwd "$i"
    done;
}

# Passwords for everyone! (the 'humans', uid >= 1000)
read -r -p "$* [y/n]: " pass
case $pass in
    [Yy]* ) cngpass ;;
    [Nn]* ) echo "Okay, let's continue" ;;
esac

# List user accounts by size
echo "Home directory space by user"
format="%8s%10s%10s   %-s\n"
printf "$format" "Dirs" "Files" "Blocks" "Directory" | tee dirsize.txt
printf "$format" "----" "-----" "------" "---------" | tee -a dirsize.txt
dir_list="/home/*"
for home_dir in $dir_list; do
    total_dirs=$(find "$home_dir" -type d | wc -l)
    total_files=$(find "$home_dir" -type f | wc -l)
    total_blocks=$(du -s "$home_dir")
    printf "$format" "$total_dirs" "$total_files" "$total_blocks" | tee -a dirsize.txt
done

#simplification for.... Stuff.
buckrun() {
cd buck-security
./buck-security --sysroot=/
cd ..
}

# Run The Trusty Ol' Buck Security
if [ $buck == 1 ]; then
    {
	buckrun;
    }
elif [ -d "./buck-security" ]; then
    {
	echo "Buck Security Detected. Run?"
	read -r -p "$* [y/n]: " runbuck
	case $runbuck in
	 [Yy]* ) buckrun ;;
	 [Nn]* ) echo "Buck Security not running." ;;
	esac
    }
else
    echo "Buck security not downloaded, so not running."
fi

# Run CHROOTKIT
if [[ $bum == 1 ]]; then
    echo -n "Run CHKROOTKIT?"
    read -r -p "$* [y/n]: " yn
    case $yn in
        [Yy]* ) chkrootkit | grep INFECTED ;;
        [Nn]* ) echo "Ah, okay. Let's continue... almost done!" ;;
        * ) echo "Invalid input! Please answer y (yes) or n (no)."
    esac
else
    echo "CHKROOTKIT not installed, so not running."
fi

# Secure Shared Memory
if [ ! "$fstab" -eq "0" ]; then
    echo "fstab already contains a tmpfs partition. Nothing to be done."
elif [ "$fstab" -eq "0" ]; then
    echo "fstab being updated to secure shared memory"
    echo "tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid     0     0" >> /etc/fstab
    echo "Shared memory secured. Reboot required"
fi
# Harden SYSCTL
echo "Hardening SYSCTL..."
# Check if sysctl entry exists comment out old entries
sysctlConfig1=$(grep -c "net.ipv4.conf.default.rp_filter" /etc/sysctl.conf)
if [ ! "$sysctlConfig1" -eq "0" ]
then
    # if entry exists use sed to search and replace - write to tmp file - move to original
    sed 's/net.ipv4.conf.default.rp_filter/#net.ipv4.conf.default.rp_filter/g' /etc/sysctl.conf > /tmp/.sysctl_config
    mv /etc/sysctl.conf /etc/sysctl.conf.backup
    mv /tmp/.sysctl_config /etc/sysctl.conf
fi
# Check if sysctl entry exists comment out old entries
sysctlConfig2=$(grep -c "net.ipv4.conf.all.rp_filter" /etc/sysctl.conf)
if [ ! "$sysctlConfig2" -eq "0" ]
then
    # if entry exists use sed to search and replace - write to tmp file - move to original
    sed 's/net.ipv4.conf.all.rp_filter/#net.ipv4.conf.all.rp_filter/g' /etc/sysctl.conf > /tmp/.sysctl_config
    mv /etc/sysctl.conf /etc/sysctl.conf.backup
    mv /tmp/.sysctl_config /etc/sysctl.conf
fi
# Check if sysctl entry exists comment out old entries
sysctlConfig3=$(grep -c "net.ipv4.icmp_echo_ignore_broadcasts" /etc/sysctl.conf)
if [ ! "$sysctlConfig3" -eq "0" ]
then
    # if entry exists use sed to search and replace - write to tmp file - move to original
    sed 's/net.ipv4.icmp_echo_ignore_broadcasts/#net.ipv4.icmp_echo_ignore_broadcasts/g' /etc/sysctl.conf > /tmp/.sysctl_config
    mv /etc/sysctl.conf /etc/sysctl.conf.backup
    mv /tmp/.sysctl_config /etc/sysctl.conf
fi
# Check if sysctl entry exists comment out old entries
sysctlConfig4=$(grep -c "net.ipv4.tcp_syncookies" /etc/sysctl.conf)
if [ ! "$sysctlConfig4" -eq "0" ]
then
    # if entry exists use sed to search and replace - write to tmp file - move to original
    sed 's/net.ipv4.tcp_syncookies/#net.ipv4.tcp_syncookies/g' /etc/sysctl.conf > /tmp/.sysctl_config
    mv /etc/sysctl.conf /etc/sysctl.conf.backup
    mv /tmp/.sysctl_config /etc/sysctl.conf
fi
# Check if sysctl entry exists comment out old entries
sysctlConfig5=$(grep -c "net.ipv4.conf.all.accept_source_route" /etc/sysctl.conf)
if [ ! "$sysctlConfig5" -eq "0" ]
then
    # if entry exists use sed to search and replace - write to tmp file - move to original
    sed 's/net.ipv4.conf.all.accept_source_route/#net.ipv4.conf.all.accept_source_route/g' /etc/sysctl.conf > /tmp/.sysctl_config
    mv /etc/sysctl.conf /etc/sysctl.conf.backup
    mv /tmp/.sysctl_config /etc/sysctl.conf
fi
# Check if sysctl entry exists comment out old entries
sysctlConfig6=$(grep -c "net.ipv6.conf.all.accept_source_route" /etc/sysctl.conf)
if [ ! "$sysctlConfig6" -eq "0" ]
then
    # if entry exists use sed to search and replace - write to tmp file - move to original
    sed 's/net.ipv6.conf.all.accept_source_route/#net.ipv6.conf.all.accept_source_route/g' /etc/sysctl.conf > /tmp/.sysctl_config
    mv /etc/sysctl.conf /etc/sysctl.conf.backup
    mv /tmp/.sysctl_config /etc/sysctl.conf
fi
# Check if sysctl entry exists comment out old entries
sysctlConfig7=$(grep -c "net.ipv4.conf.default.accept_source_route" /etc/sysctl.conf)
if [ ! "$sysctlConfig7" -eq "0" ]
then
    # if entry exists use sed to search and replace - write to tmp file - move to original
    sed 's/net.ipv4.conf.default.accept_source_route/#net.ipv4.conf.default.accept_source_route/g' /etc/sysctl.conf > /tmp/.sysctl_config
    mv /etc/sysctl.conf /etc/sysctl.conf.backup
    mv /tmp/.sysctl_config /etc/sysctl.conf
fi
# Check if sysctl entry exists comment out old entries
sysctlConfig8=$(grep -c "net.ipv6.conf.default.accept_source_route" /etc/sysctl.conf)
if [ ! "$sysctlConfig8" -eq "0" ]
then
    # if entry exists use sed to search and replace - write to tmp file - move to original
    sed 's/net.ipv6.conf.default.accept_source_route/#net.ipv6.conf.default.accept_source_route/g' /etc/sysctl.conf > /tmp/.sysctl_config
    mv /etc/sysctl.conf /etc/sysctl.conf.backup
    mv /tmp/.sysctl_config /etc/sysctl.conf
fi
# Check if sysctl entry exists comment out old entries
sysctlConfig9=$(grep -c "net.ipv4.conf.all.log_martians" /etc/sysctl.conf)
if [ ! "$sysctlConfig9" -eq "0" ]
then
    # if entry exists use sed to search and replace - write to tmp file - move to original
    sed 's/net.ipv4.conf.all.log_martians/#net.ipv4.conf.all.log_martians/g' /etc/sysctl.conf > /tmp/.sysctl_config
    mv /etc/sysctl.conf /etc/sysctl.conf.backup
    mv /tmp/.sysctl_config /etc/sysctl.conf
fi
{
    echo "Writing new sysctl configuration settings..."
    echo "net.ipv4.conf.default.rp_filter = 1"
    echo "net.ipv4.conf.all.rp_filter = 1"
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1"
    echo "net.ipv4.tcp_syncookies = 1"
    echo "net.ipv4.conf.all.accept_source_route = 0"
    echo "net.ipv6.conf.all.accept_source_route = 0"
    echo "net.ipv4.conf.default.accept_source_route = 0"
    echo "net.ipv6.conf.default.accept_source_route = 0"
    echo "net.ipv4.conf.all.log_martians = 1"
    echo "sysctl settings update complete"
} >> /etc/sysctl.conf

# Prevent IP Spoofing
echo "order bind,hosts" >> /etc/host.conf
echo "nospoof on" >> /etc/host.conf

echo "Script completed. Please remember to look at the output of the script; and check buck-security results."
echo "Also look at CHKROOTKIT's results, as that may shed some light on some *points* of interest."
echo "Don't forget to sneak a look at \"dirsize.txt\" in this directory; it could help you find media files."

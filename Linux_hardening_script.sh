#!/bin/bash
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
RESET=`tput sgr0`
sudo apt-get install tput
echo "Installing necessary tools..."
sudo apt-get update
sudo apt-get install -y mokutil sbsigntool

# Check if Secure Boot is enabled
echo "Checking Secure Boot status..."
if mokutil --sb-state | grep -q 'SecureBoot enabled'; then
    echo "${GREEN}Secure Boot is already enabled.${RESET}"
else
    echo "${RED}Secure Boot is disabled. You need to enable it in your BIOS settings.${RESET}"
fi
#!/bin/bash
if 	grep -q 'set superusers=' /etc/grub.d/40_custom; then
    	echo "${GREEN}A user with a password already exists in the GRUB configuration.${RESET}"
else
	# Prompt for GRUB username
	read -p "Enter username for GRUB: "  grub_username

	# Prompt for password
	read -p "Enter password for $grub_username:" grub_password

	# Use 'expect' to automate password input for grub-mkpasswd-pbkdf2
	ENCRYPTED_PASS=$(expect -c "
	spawn grub-mkpasswd-pbkdf2
	expect \"Enter password:\"
	send \"$grub_password\r\"
	expect \"Reenter password:\"
	send \"$grub_password\r\"
	expect eof
	" | awk '/PBKDF2 hash of your password is/ {print $NF}')

	# Check if password hash was successfully created
	if [ -z "$ENCRYPTED_PASS" ]; then
    		echo "${RED}Failed to create encrypted password.${RESET}"
    		exit 1
	fi

	# Add username and password to GRUB configuration
	echo "set superusers=\"$grub_username\"" | sudo tee -a /etc/grub.d/40_custom
	echo "password_pbkdf2 $grub_username $ENCRYPTED_PASS" | sudo tee -a /etc/grub.d/40_custom

	# Update GRUB
	sudo update-grub
	echo "${GREEN}Grub user created successfully!${RESET}"
fi
#!/bin/bash

# Path to the GRUB configuration file
GRUB_CONFIG="/etc/default/grub"

# Parameters to add if not already present
PARAMS_TO_ADD="splash intel_iommu=on"

# Backup the original GRUB configuration file
sudo cp "$GRUB_CONFIG" "${GRUB_CONFIG}.backup"

# Check if the parameters are already in the GRUB_CMDLINE_LINUX_DEFAULT line
if ! grep -q "$PARAMS_TO_ADD" "$GRUB_CONFIG"; then
    # Append the parameters
    sudo sed -i "/^GRUB_CMDLINE_LINUX_DEFAULT=/ s/\"$/ $PARAMS_TO_ADD\"/" "$GRUB_CONFIG"

    # Update GRUB to apply the changes
    sudo update-grub
    echo "${GREEN}IOMMU force parameters added and GRUB updated, check if it's activated in BIOS/UEFI. ${RESET}"
else
    echo "${GREEN}IOMMU force parameters already exist, check if it's activated in BIOS/UEFI. ${RESET}"
fi
#!/bin/bash

echo "${YELLOW}Adding recommended memory configuration options${RESET}"
add_grub(){
GRUB_CONFIG="/etc/default/grub"

# Parameters to add if not already present
PARAMS_TO_ADD="$1"

# Backup the original GRUB configuration file
sudo cp "$GRUB_CONFIG" "${GRUB_CONFIG}.backup"

# Check if the parameters are already in the GRUB_CMDLINE_LINUX_DEFAULT line
if ! grep -q "$PARAMS_TO_ADD" "$GRUB_CONFIG"; then
    # Append the parameters
    sudo sed -i "/^GRUB_CMDLINE_LINUX_DEFAULT=/ s/\"$/ $PARAMS_TO_ADD\"/" "$GRUB_CONFIG"

    # Update GRUB to apply the changes
    sudo update-grub
    echo "${GREEN}Parameter $1 added${RESET}"
else
    echo "${BLUE}Parameter $1 already exists${RESET}"
fi
}
add_grub "page_poison=on"
add_grub "pti=on"
add_grub "slab_nomerge=yes"
add_grub "slub_debug=FZP"
add_grub "spec_store_bypass_disable=seccomp"
add_grub "spectre_v2=on"
add_grub "mds=full,nosmt"
add_grub "mce=0"
add_grub "page_alloc.shuffle=1"
add_grub "rng_core.default_quality=500"

echo "${YELLOW}Adding recommended kernel configuration options${RESET}"
cat <<EOF >> "/etc/sysctl.conf"
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.pid_max=65536
kernel.perf_cpu_time_max_percent=1
kernel.perf_event_paranoid=2
kernel.randomize_va_space=2
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.panic_on_oops=1
EOF
echo "${GREEN}Done.${RESET}"
cat <<EOF >>"/etc/sysctl.conf"
kernel.modules_disabled=1
EOF

echo "${YELLOW}Adding recommended PROCESS configuration options${RESET}"
cat <<EOF >>"/etc/sysctl.conf"
security=yama
kernel.yama.ptrace_scope=1
EOF
echo "${GREEN}Done.${RESET}"
echo "${YELLOW}Adding recommended NETWORK configuration options${RESET}"
cat <<EOF >>"/etc/sysctl.conf"
# Mitigation of the dispersion effect of the kernel JIT at the cost of a
# compromise on the associated performance.
net.core.bpf_jit_harden=2
# No routing between interfaces. This option is special and may
# cause modifications to other options. By setting this option early
# we make sure that the configuration of the following options does
# not change.
net.ipv4.ip_forward=0
# Consider as invalid the packets received from outside whose source
# is the 127/8 network.
net.ipv4.conf.all.accept_local=0
# Deny receipt of ICMP redirect packet. The suggested setting of this
# option is to be strongly considered in the case of routers which must not
# depend on an external element to determine the calculation of a route. Even
# for non-router machines , this setting protects against
# traffic diversions with ICMP redirect packets.
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.shared_media=0
# Deny the source routing header information supplied by the
# packet to determine its route.
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
# Prevent the Linux kernel from handling the ARP table globally. By default ,
# it can respond to an ARP request from an X interface with information
# from an interface Y. This behavior is problematic for routers and
# equipment of a high availability system (VRRP, etc.).
net.ipv4.conf.all.arp_filter=1
# Respond to ARP requests only if the source and destination addresses are on
# the same network and come from the same interface on which the packet was
received.
# Note that the configuration of this option is to be studied according to the
# use case.
net.ipv4.conf.all.arp_ignore=2
# Refuse the routing of packets whose source or destination address is that
# of the local loopback. This prohibits the transmission of packets with
# source network 127/8.
net.ipv4.conf.all.route_localnet=0
# Ignore gratuitous ARP requests. This configuration is
# effective against ARP poisoning attacks but only applicable
# in association with one or more controlled ARP proxies.
# This option can be problematic on networks with devices
# in a high availability setup (VRRP, etc.).
net.ipv4.conf.all.drop_gratuitous_arp=1
# Check that the source address of packets received on a given interface
# would have been contacted via this same interface. Otherwise , the packet
# is ignored. Depending on usage , the value 1 can increase the verification to
# all the interfaces , when the device is a router for which the calculation of
# routes is dynamic. The interested reader is referred to RFC3704 for all
# details for this feature.
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
# This option should only be set to 1 in the case of a router because for such
# equipment sending ICMP redirect is normal behaviour. A non-routing
# equipment has no reason to receive a flow for which it is not the recipient
# and therefore to send an ICMP redirect packet.
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.send_redirects=0
# Ignore responses that do not comply with RFC 1122
net.ipv4.icmp_ignore_bogus_error_responses=1
# Increase the range for ephemeral ports
net.ipv4.ip_local_port_range=32768 65535
# RFC 1337
net.ipv4.tcp_rfc1337=1
# Use SYN cookies to prevent SYN flood type attacks.
net.ipv4.tcp_syncookies=1
#disabling ipv6
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.all.disable_ipv6=1
EOF
echo "${GREEN}Done.${RESET}"
echo "${YELLOW}Adding recommended FILE configuration options${RESET}"
cat <<EOF >> "/etc/sysctl.conf"
# Disable coredump creation for setuid executables
# Note that it is possible to disable all coredumps with the
# configuration CONFIG_COREDUMP=n
fs.suid_dumpable = 0
# Available from version 4.19 of the Linux kernel , allows to prohibit
# opening FIFOs and "regular" files that are not owned by the user
# in sticky folders for everyone to write.
fs.protected_fifos=2
fs.protected_regular=2
# Restrict the creation of symbolic links to files that the user
# owns. This option is part of the vulnerability prevention mechanisms
# of the Time of Check - Time of Use (Time of Check -
# Time of Use)
fs.protected_symlinks=1
# Restrict the creation of hard links to files whose user is
# owner. This sysctl is part of the prevention mechanisms against
# Time of Check - Time of Use vulnerabilities , but also against the
# possibility of retaining access to obsolete files
fs.protected_hardlinks=1
EOF
echo "${YELLOW}Adding HARDWARE INDEPENDENT configuration options${RESET}"
cat <<EOF >> "/etc/sysctl.conf"
# This option replaced CONFIG_DEBUG_RODATA in the kernel (> = 4.11)
# which was a dependency of CONFIG_DEBUG_KERNEL
CONFIG_STRICT_KERNEL_RWX=y
# CONFIG_ARCH_OPTIONAL_KERNEL_RWX and
# CONFIG_ARCH_HAS_STRICT_KERNEL_RWX are dependencies of
# CONFIG_STRICT_KERNEL_RWX
CONFIG_ARCH_OPTIONAL_KERNEL_RWX=y
CONFIG_ARCH_HAS_STRICT_KERNEL_RWX=y
# Check and report unsafe memory mapping permissions , for
# example , when kernel pages are writable and executable.
# This option is not available on all architectures
# hardware (x86> = 4.4, arm64 > = 4.10, etc.).
CONFIG_DEBUG_WX=y
# Disable the file system used only for debugging. Protecting this file
# system takes additional work.
CONFIG_DEBUG_FS=n
# Starting with kernel version 4.18, these options add
# -fstack -protector -strong at compilation time to strengthen
# the canary stack , it is necessary to have a version of GCC at least
# equal to 4.9.
# Before version 4.18 of the linux kernel , you must use the options
# CONFIG_CC_STACKPROTECTOR and
# CONFIG_CC_STACKPROTECTOR_STRONG
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
# Prohibits direct access to physical memory.
# If necessary and only in this case, it is possible to activate a
# strict access to memory , thus limiting its access , with options
# CONFIG_STRICT_DEVMEM=y and CONFIG_IO_STRICT_DEVMEM=y
#CONFIG_DEVMEM is not set
# Detects stack corruption during the call to the scheduler
CONFIG_SCHED_STACK_END_CHECK=y
# Impose a check of the limits of the memory mapping of the process
# at the time of data copies.
CONFIG_HARDENED_USERCOPY=y
# Forbid the return to a verification of the mapping with the allocator if
# the previous option failed.
#CONFIG_HARDENED_USERCOPY_FALLBACK is not set
# Added cover pages between kernel stacks. This protects against the effects
# of edge of stack overflows (this option is not supported on all
# architectures).
CONFIG_VMAP_STACK=y
# Impose exhaustive checks on kernel reference counters (<=5.4)
CONFIG_REFCOUNT_FULL=y
# Check the memory copy actions that could cause corruption
# of structure in the kernel functions str*() and mem*(). This verification is
# performed at compile time and at runtime.
CONFIG_FORTIFY_SOURCE=y
# Disable the dangerous use of ACPI, which can lead to direct writing
# in physical memory.
#CONFIG_ACPI_CUSTOM_METHOD is not set
# Prohibit direct access to kernel memory from userspace (<=5.12)
#CONFIG_DEVKMEM is not set
# Prohibits provision of kernel image layout
#CONFIG_PROC_KCORE is not set
# Disable VDSO backward compatibility , which makes it impossible
# to use ASLR
#CONFIG_COMPAT_VDSO is not set
# Prevent unprivileged users from retrieving kernel addresses
# with dmesg (8)
CONFIG_SECURITY_DMESG_RESTRICT=y
# Activate retpolines which are necessary to protect yourself from Spectre v2
# GCC> = 7.3.0 is required.
CONFIG_RETPOLINE=y
# Disable the vsyscall table. It is no longer required by libc and is a
# potential source of ROP gadgets.
CONFIG_LEGACY_VSYSCALL_NONE=y
CONFIG_LEGACY_VSYSCALL_EMULATE=n
CONFIG_LEGACY_VSYSCALL_XONLY=n
CONFIG_X86_VSYSCALL_EMULATION=n
# Check the authorisation data structures
CONFIG_DEBUG_CREDENTIALS=y
# Check the notifications data structures
CONFIG_DEBUG_NOTIFIERS=y
# Check kernel lists
CONFIG_DEBUG_LIST=y
# Check the kernel Scatter -Gather tables.
CONFIG_DEBUG_SG=y
# Generate a call to BUG() if corruption is detected.
CONFIG_BUG_ON_DATA_CORRUPTION=y
# Randomly position the free block chaining information of the allocator.
CONFIG_SLAB_FREELIST_RANDOM=y
# CONFIG_SLAB is a dependency of CONFIG_SLAB_FREELIST_RANDOM
CONFIG_SLUB=y
# Protects integrity of the allocator 's metadata.
CONFIG_SLAB_FREELIST_HARDENED=y
# Starting with kernel version 4.13, this option disables the merge of
# SLAB caches
CONFIG_SLAB_MERGE_DEFAULT=n
# Activates the checking of the memory allocator structures and resets
# to zero the zones allocated when they are released (requires the
# activation of the page_poison=on memory configuration option
# added to the list of kernel parameters during boot). It is better to use
# the slub_debug memory configuration option added to the list of
# kernel parameters during boot as it allows finer management
# from the debug slub.
CONFIG_SLUB_DEBUG=y
# Clean up memory pages when they are freed.
CONFIG_PAGE_POISONING=y
# Deep cleaning disabled. This option comes at a significant cost;
# however if the performance impact is compatible with the need
# operational of the equipment , it is recommended to activate it. (<=5.10)
CONFIG_PAGE_POISONING_NO_SANITY=y
# The cleaning of the memory pages is carried out with a rewrite
# of zeros in place of the data (<=5.10)
CONFIG_PAGE_POISONING_ZERO=y
# Disable backward compatibility with brk () which makes it impossible to
# implementation of brk () with ASLR.
#CONFIG_COMPAT_BRK is not set
# Activation of module support
CONFIG_MODULES=y
# This option replaced CONFIG_DEBUG_SET_MODULE_RONX
# in the kernel (> = 4.11)
CONFIG_STRICT_MODULE_RWX=y
# This option replaced CONFIG_DEBUG_SET_MODULE_RONX
# in the kernel (> = 4.11)
CONFIG_MODULE_SIG=y
# Prevent loading modules that are unsigned or signed with a key that
# does not belong to us.
CONFIG_MODULE_SIG_FORCE=y
# Activate CONFIG_MODULE_SIG_ALL allows signing all modules
# automatically during the "make modules_install" step, without this option
# modules must be signed manually using the script
# scripts/sign-file. The CONFIG_MODULE_SIG_ALL option
# depends on CONFIG_MODULE_SIG and CONFIG_MODULE_SIG_FORCE ,
# so they must be enabled.
CONFIG_MODULE_SIG_ALL=y
# Module signing uses SHA512 as hash function
CONFIG_MODULE_SIG_SHA512=y
CONFIG_MODULE_SIG_HASH="sha512"
# Specifies the path to the file containing both the private key and its
# X.509 certificate in PEM format used for signing modules ,
# relative to the root of the kernel.
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
# Report on the conditions of the call to the macro kernel BUG ()
# and kill the process that initiated the call. Not setting this variable
# may hide a number of critical errors.
CONFIG_BUG=y
# Shut down the system in the event of a critical error to cut short any
# erroneous behavior.
CONFIG_PANIC_ON_OOPS=y
# Prevents restarting of the machine after a panic which cuts short
# any attempted brute force attack. This obviously has a strong impact
# on production servers.
CONFIG_PANIC_TIMEOUT=-1
# Enables the ability to filter system calls made by an application.
CONFIG_SECCOMP=y
# Activate the possibility of using BPF (Berkeley Packet Filter) scripts.
CONFIG_SECCOMP_FILTER=y
# Enables Linux kernel security primitives , required for LSMs.
CONFIG_SECURITY=y
# Active Yama, which allows to simply limit the use of the system call
# ptrace (). Once the security modules used by the system
# have been selected , support for other security modules should be disabled
# in order to reduce the attack surface.
CONFIG_SECURITY_YAMA=y
# Ensure kernel structures associated with LSMs are always mapped
# read-only after system boot. In the event that SELinux is
# used, make sure that CONFIG_SECURITY_SELINUX_DISABLE is not set,
# for this option to be available. It is then no longer possible to
# disable an LSM after the kernel has booted. It is however still
# possible to do this by modifying the kernel command line. For the
# 4.18 kernel the present LSMs are: AppArmor , LoadPin , SELinux , Smack ,
# TOMOYO and Yama.
#CONFIG_SECURITY_WRITABLE_HOOKS is not set
# Enable compiler plugins support (implies the use of GCC).
CONFIG_GCC_PLUGINS=y
# Amplify entropy generation at equipment startup for those
# having inappropriate entropy sources
CONFIG_GCC_PLUGIN_LATENT_ENTROPY=y
# Clean up the contents of the stack at the time of the exit system call.
CONFIG_GCC_PLUGIN_STACKLEAK=y
# Force initialization of structures in memory to avoid data leakage by
# superimposition with an old structure.
CONFIG_GCC_PLUGIN_STRUCTLEAK=y
# Globalization of the previous option in the case of the passage
# of structure by reference between functions if they have uninitialized fields
CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL=y
# Build a random memory map for the kernel system structures.
# This option has a strong impact on performance. The option
# CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE=y should be used
# instead if this impact is not acceptable.
CONFIG_GCC_PLUGIN_RANDSTRUCT=y
# Disable the IPv6 plan
#CONFIG_IPV6 option is not set.
# Used to prevent SYN flood type attacks.
CONFIG_SYN_COOKIES=y
# Prohibits the execution of a new kernel image after reboot.
#CONFIG_KEXEC is not set
# Prohibits switching to hibernation mode, which allows you to
# substitute the image kernel without his knowledge.
#CONFIG_HIBERNATION is not set
# Disable arbitrary binary format support.
#CONFIG_BINFMT_MISC is not set
# Impose the use of modern ptys (devpts) which number and use
# can be controlled
#CONFIG_LEGACY_PTYS is not set
# If module support is not absolutely necessary , it must be
# disabled.
#CONFIG_MODULES is not set
EOF
echo "${GREEN}Done.${RESET}"
echo "${YELLOW}Adding HARDWARE DEPENDENT configuration options${RESET}"
echo "choose your architecture: "
echo "${MAGENTA}1: 32 bits"
echo "2:  64 bits"
echo "3:  ARM"
echo "4: ARM 64bits${RESET}"
read -p "Enter your choice" choix
case $choix in
	1)
		cat <<EOF >> "/etc/sysctl.conf"
		# Enable support for physical address extensions , which is a prerequisite
		# for support of the NX permission bit in the page table which allows
		# certain pages to be marked as non-executable.
		CONFIG_HIGHMEM64G=y
		CONFIG_X86_PAE=y
		# Prohibits the use of memory addresses below a certain value
		# (countermeasure against null pointer dereference).
		CONFIG_DEFAULT_MMAP_MIN_ADDR=65536
		# Makes the base address of the kernel unpredictable.
		# This option complicates the task of an attacker.
		CONFIG_RANDOMIZE_BASE=y
		EOF
		;;
	2)
		cat <<EOF >> "/etc/sysctl.conf"
		# Activate full 64-bit mode.
		CONFIG_X86_64=y
		# Prohibits the use of memory addresses below a certain value
		# (countermeasure against null pointer dereference).
		CONFIG_DEFAULT_MMAP_MIN_ADDR=65536
		# Makes the base address of the kernel unpredictable , this option complicates
		# the task of an attacker.
		CONFIG_RANDOMIZE_BASE=y
		# Makes the address to which kernel components are exposed in
		# the process address space unpredictable.
		CONFIG_RANDOMIZE_MEMORY=y
		# Countermeasure to the Meltdown attack.
		CONFIG_PAGE_TABLE_ISOLATION=y
		# Disable 32-bit backwards compatibility , which helps reduce the
		# attack surface but prevents 32-bit binaries from being executed.
		#CONFIG_IA32_EMULATION is not set
		# Prohibits the per-process overloading of the Local Descriptor Table
		# (mechanism linked to the use of segmentation).
		EOF
		;;
	3)
		cat <<EOF >> "/etc/sysctl.conf"
		# Prohibits the use of memory addresses below a certain value
		# (countermeasure against null pointer dereference).
		CONFIG_DEFAULT_MMAP_MIN_ADDR=32768
		# Maximizes the size of the virtual memory of the processes (and of the ASLR
		# related).
		CONFIG_VMSPLIT_3G=y
		# Prohibits RWX memory mappings
		CONFIG_STRICT_MEMORY_RWX=y
		# Prohibits access by the kernel to user memory (mechanism
		# equivalent on ARM to SMAP on x86_64).
		CONFIG_CPU_SW_DOMAIN_PAN=y
		# This option of compatibility with the old ABI ARM is dangerous and
		# paves the way for various attacks.
		#CONFIG_OABI_COMPAT is not set
		EOF
		;;
	4)
		cat <<EOF >> "/etc/sysctl.conf"
		# Prohibits the use of memory addresses below a certain value
		# (countermeasure against null pointer dereference).
		CONFIG_DEFAULT_MMAP_MIN_ADDR=32768
		# Makes the base address of the kernel unpredictable , this option complicates
		# the task of an attacker. The entropy necessary for the generation
		# of the hazard must be provided by the UEFI or, failing that, by the
		# bootloader.
		CONFIG_RANDOMIZE_BASE=y
		# Prohibits access by the kernel to user memory (mechanism
		# equivalent on ARM to SMAP on 86_64).
		CONFIG_ARM64_SW_TTBR0_PAN=y
		# Countermeasure to the Meltdown attack.
		CONFIG_UNMAP_KERNEL_AT_EL0=y
		EOF
		;;
	*)
		echo "${RED}Invalid choice${RESET}"
		;;
esac
echo "${GREEN}Done.${RESET}"

# Path to the fstab file
FSTAB="/etc/fstab"

# Backup the original fstab file
cp "$FSTAB" "${FSTAB}.backup"

# Comment out the line for /boot in fstab
sed -i '/\/boot/ s/^/#/' "$FSTAB"

# Change permissions of /boot to be accessible by root only
chmod 700 /boot
echo "Restricted /boot to root only."


# -Enable the sticky bit on directories
echo -e "Enabling the sticky bit on all directories writable by everyone..."
find / -type d \( -perm -0002 -a \! -perm -1000 \) -exec chmod o+t {} \; 2>/dev/null
echo -e "${GREEN}Sticky bit enabled on directories.${RESET}"

# Change ownership of directories writable by everyone and not owned by root
echo -e "Changing ownership of directories writable by everyone and not owned by root..."
find / -type d -perm -0002 -a \! -uid 0 -exec chown root {} \; 2>/dev/null
echo -e "${GREEN}Ownership changed for directories.${RESET}"

# Pluggable Authentication Module

# Update PAM files for su
echo -e "Updating /etc/pam.d/su..."
cat <<EOF >> /etc/pam.d/su
# Limite l'accès à root via su aux membres du groupe 'wheel '
auth required pam_wheel.so use_uid root_only
EOF
echo -e "${GREEN}Update complete for /etc/pam.d/su.${RESET}"

# Update PAM files for su-l
echo -e "Updating /etc/pam.d/su-l..."
cat <<EOF >> /etc/pam.d/su-l
# Limite l'accès à root via su aux membres du groupe 'wheel '
auth required pam_wheel.so use_uid root_only
EOF
echo -e "${GREEN}Update complete for /etc/pam.d/su-l.${RESET}"

# Update PAM files for passwd
echo -e "Updating /etc/pam.d/passwd..."
cat <<EOF >> /etc/pam.d/passwd
# Au moins 12 caractères de 3 classes différentes parmi les majuscules,
# les minuscules, les chiffres et les autres en interdisant la répétition
# d'un caractère
password required pam_pwquality.so minlen=12 minclass=3 dcredit=0 ucredit=0 lcredit=0 ocredit=0 maxrepeat=1
EOF
echo -e "${GREEN}Update complete for /etc/pam.d/passwd.${RESET}"

# Update PAM files for login
echo -e "Updating /etc/pam.d/login..."
cat <<EOF >> /etc/pam.d/login
# Blocage du compte pendant 5 min après 3 échecs
auth required pam_faillock.so deny=3 unlock_time=300
EOF
echo -e "${GREEN}Update complete for /etc/pam.d/login.${RESET}"

# Update PAM files for sshd
echo -e "Updating /etc/pam.d/sshd..."
cat <<EOF >> /etc/pam.d/sshd
# Blocage du compte pendant 5 min après 3 échecs
auth required pam_faillock.so deny=3 unlock_time=300
EOF
echo -e "${GREEN}Update complete for /etc/pam.d/sshd.${RESET}"



# Configure PAM for password protection
echo "Configuring PAM for password protection..."

# Check if yescrypt is supported, otherwise use SHA-512crypt
if grep -q "pam_unix.so.*yescrypt" /etc/pam.d/common-password; then
    echo "yescrypt is supported."
    # Configure PAM with yescrypt
    cat <<EOF >> /etc/pam.d/common-password
password required pam_unix.so obscure yescrypt rounds=11
EOF
else
    echo "yescrypt is not supported. Using SHA-512crypt..."
    # Configure PAM with SHA-512crypt
    cat <<EOF >> /etc/pam.d/common-password
password required pam_unix.so obscure sha512 rounds=65536
EOF
fi

echo -e "${GREEN}PAM configured for password protection.${RESET}"

echo " Setting up a logging system with auditd. "
# Check if auditd is installed
if ! command -v auditd &>/dev/null; then
    echo -e "${GREEN}Installing auditd...${RESET}"
    # Install auditd
    apt-get install -y auditd
    echo -e "${GREEN}auditd installed.${RESET}"
fi

# Configure auditd rules
echo -e "${GREEN}Configuring auditd rules...${RESET}"

# Create or update the audit rules file
cat <<EOF > /etc/audit/audit.rules
# Exécution de insmod , rmmod et modprobe
-w /sbin/insmod -p x
-w /sbin/modprobe -p x
-w /sbin/rmmod -p x
# Sur les distributions GNU/Linux récentes , insmod , rmmod et modprobe sont
# des liens symboliques de kmod
-w /bin/kmod -p x
# Journaliser les modifications dans /etc/
-w /etc/ -p wa
# Surveillance de montage/démontage
-a exit,always -S mount -S umount2
# Appels de syscalls x86 suspects
-a exit,always -S ioperm -S modify_ldt
# Appels de syscalls qui doivent être rares et surveillés de près
-a exit,always -S get_kernel_syms -S ptrace
-a exit,always -S prctl
# Rajout du monitoring pour la création ou suppression de fichiers
# Ces règles peuvent avoir des conséquences importantes sur les
# performances du système
-a exit,always -F arch=b64 -S unlink -S rmdir -S rename
-a exit,always -F arch=b64 -S creat -S open -S openat -F exit=-EACCES
-a exit,always -F arch=b64 -S truncate -S ftruncate -F exit=-EACCES
# Rajout du monitoring pour le chargement , le changement et
# le déchargement de module noyau
-a exit,always -F arch=b64 -S init_module -S delete_module
-a exit,always -F arch=b64 -S finit_module
# Verrouillage de la configuration de auditd
-e 2
EOF

echo -e "${GREEN}Auditd rules configured.${RESET}"

# Restart auditd for changes to take effect
echo -e "${GREEN}Restarting auditd...${RESET}"
service auditd restart

echo -e "${GREEN}Auditd configured and restarted.${RESET}"


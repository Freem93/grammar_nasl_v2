#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-1908.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44621);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2009-1633", "CVE-2009-2848", "CVE-2009-2903", "CVE-2009-2910", "CVE-2009-3002", "CVE-2009-3238", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726", "CVE-2009-3939", "CVE-2009-4021", "CVE-2009-4138", "CVE-2009-4308", "CVE-2009-4536", "CVE-2009-4538", "CVE-2010-0003", "CVE-2010-0007");

  script_name(english:"openSUSE Security Update : kernel (kernel-1908)");
  script_summary(english:"Check for the kernel-1908 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for openSUSE 11.0 fixes some bugs and several
security problems.

The following security issues are fixed: CVE-2009-4536:
drivers/net/e1000/e1000_main.c in the e1000 driver in the Linux kernel
handles Ethernet frames that exceed the MTU by processing certain
trailing payload data as if it were a complete frame, which allows
remote attackers to bypass packet filters via a large packet with a
crafted payload.

CVE-2009-4538: drivers/net/e1000e/netdev.c in the e1000e driver in the
Linux kernel does not properly check the size of an Ethernet frame
that exceeds the MTU, which allows remote attackers to have an
unspecified impact via crafted packets.

CVE-2010-0007: Missing CAP_NET_ADMIN checks in the ebtables netfilter
code might have allowed local attackers to modify bridge firewall
settings.

CVE-2010-0003: An information leakage on fatal signals on x86_64
machines was fixed.

CVE-2009-4138: drivers/firewire/ohci.c in the Linux kernel, when
packet-per-buffer mode is used, allows local users to cause a denial
of service (NULL pointer dereference and system crash) or possibly
have unknown other impact via an unspecified ioctl associated with
receiving an ISO packet that contains zero in the payload-length
field.

CVE-2009-4308: The ext4_decode_error function in fs/ext4/super.c in
the ext4 filesystem in the Linux kernel before 2.6.32 allows
user-assisted remote attackers to cause a denial of service (NULL
pointer dereference), and possibly have unspecified other impact, via
a crafted read-only filesystem that lacks a journal.

CVE-2009-3939: The poll_mode_io file for the megaraid_sas driver in
the Linux kernel 2.6.31.6 and earlier has world-writable permissions,
which allows local users to change the I/O mode of the driver by
modifying this file.

CVE-2009-4021: The fuse_direct_io function in fs/fuse/file.c in the
fuse subsystem in the Linux kernel before 2.6.32-rc7 might allow
attackers to cause a denial of service (invalid pointer dereference
and OOPS) via vectors possibly related to a memory-consumption attack.

CVE-2009-3547: A race condition in the pipe(2) systemcall could be
used by local attackers to hang the machine. The kernel in Moblin 2.0
uses NULL ptr protection which avoids code execution possbilities.

CVE-2009-2903: Memory leak in the appletalk subsystem in the Linux
kernel 2.4.x through 2.4.37.6 and 2.6.x through 2.6.31, when the
appletalk and ipddp modules are loaded but the ipddp'N' device is not
found, allows remote attackers to cause a denial of service (memory
consumption) via IP-DDP datagrams.

CVE-2009-3621: net/unix/af_unix.c in the Linux kernel 2.6.31.4 and
earlier allows local users to cause a denial of service (system hang)
by creating an abstract-namespace AF_UNIX listening socket, performing
a shutdown operation on this socket, and then performing a series of
connect operations to this socket.

CVE-2009-3612: The tcf_fill_node function in net/sched/cls_api.c in
the netlink subsystem in the Linux kernel 2.6.x before 2.6.32-rc5, and
2.4.37.6 and earlier, does not initialize a certain tcm__pad2
structure member, which might allow local users to obtain sensitive
information from kernel memory via unspecified vectors.

CVE-2009-3620: The ATI Rage 128 (aka r128) driver in the Linux kernel
before 2.6.31-git11 does not properly verify Concurrent Command Engine
(CCE) state initialization, which allows local users to cause a denial
of service (NULL pointer dereference and system crash) or possibly
gain privileges via unspecified ioctl calls.

CVE-2009-3726: The nfs4_proc_lock function in fs/nfs/nfs4proc.c in the
NFSv4 client in the Linux kernel before 2.6.31-rc4 allows remote NFS
servers to cause a denial of service (NULL pointer dereference and
panic) by sending a certain response containing incorrect file
attributes, which trigger attempted use of an open file that lacks
NFSv4 state.

CVE-2009-3286: NFSv4 in the Linux kernel 2.6.18, and possibly other
versions, does not properly clean up an inode when an O_EXCL create
fails, which causes files to be created with insecure settings such as
setuid bits, and possibly allows local users to gain privileges,
related to the execution of the do_open_permission function even when
a create fails.

CVE-2009-2910: arch/x86/ia32/ia32entry.S in the Linux kernel before
2.6.31.4 on the x86_64 platform does not clear certain kernel
registers before a return to user mode, which allows local users to
read register values from an earlier process by switching an ia32
process to 64-bit mode.

CVE-2009-3238: The get_random_int function in drivers/char/random.c in
the Linux kernel before 2.6.30 produces insufficiently random numbers,
which allows attackers to predict the return value, and possibly
defeat protection mechanisms based on randomization, via vectors that
leverage the function's tendency to 'return the same value over and
over again for long stretches of time.'

CVE-2009-2848: The execve function in the Linux kernel, possibly
2.6.30-rc6 and earlier, does not properly clear the
current->clear_child_tid pointer, which allows local users to cause a
denial of service (memory corruption) or possibly gain privileges via
a clone system call with CLONE_CHILD_SETTID or CLONE_CHILD_CLEARTID
enabled, which is not properly handled during thread creation and
exit.

CVE-2009-3002: The Linux kernel before 2.6.31-rc7 does not initialize
certain data structures within getname functions, which allows local
users to read the contents of some kernel memory locations by calling
getsockname on (1) an AF_APPLETALK socket, related to the
atalk_getname function in net/appletalk/ddp.c; (2) an AF_IRDA socket,
related to the irda_getname function in net/irda/af_irda.c; (3) an
AF_ECONET socket, related to the econet_getname function in
net/econet/af_econet.c; (4) an AF_NETROM socket, related to the
nr_getname function in net/netrom/af_netrom.c; (5) an AF_ROSE socket,
related to the rose_getname function in net/rose/af_rose.c; or (6) a
raw CAN socket, related to the raw_getname function in net/can/raw.c.

CVE-2009-1633: Multiple buffer overflows in the cifs subsystem in the
Linux kernel before 2.6.29.4 allow remote CIFS servers to cause a
denial of service (memory corruption) and possibly have unspecified
other impact via (1) a malformed Unicode string, related to Unicode
string area alignment in fs/cifs/sess.c; or (2) long Unicode
characters, related to fs/cifs/cifssmb.c and the cifs_readdir function
in fs/cifs/readdir.c."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=421732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=441062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=526368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=534372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=536467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=539878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=541648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=541658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=543740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=547131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=550001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=552775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=567376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=570606"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 119, 189, 200, 264, 310, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acerhk-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acx-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:appleir-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:at76_usb-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:atl2-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aufs-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gspcav-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ivtv-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kqemu-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nouveau-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:omnibook-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcc-acpi-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tpctl-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uvcvideo-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wlan-ng-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"acerhk-kmp-debug-0.5.35_2.6.25.20_0.6-98.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"acx-kmp-debug-20080210_2.6.25.20_0.6-4.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"appleir-kmp-debug-1.1_2.6.25.20_0.6-108.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"at76_usb-kmp-debug-0.17_2.6.25.20_0.6-2.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"atl2-kmp-debug-2.0.4_2.6.25.20_0.6-4.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"aufs-kmp-debug-cvs20080429_2.6.25.20_0.6-13.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"dazuko-kmp-debug-2.3.4.4_2.6.25.20_0.6-42.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"drbd-kmp-debug-8.2.6_2.6.25.20_0.6-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"gspcav-kmp-debug-01.00.20_2.6.25.20_0.6-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"iscsitarget-kmp-debug-0.4.15_2.6.25.20_0.6-63.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ivtv-kmp-debug-1.0.3_2.6.25.20_0.6-66.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-debug-2.6.25.20-0.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-default-2.6.25.20-0.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-pae-2.6.25.20-0.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-source-2.6.25.20-0.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-syms-2.6.25.20-0.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-vanilla-2.6.25.20-0.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-xen-2.6.25.20-0.6") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kqemu-kmp-debug-1.3.0pre11_2.6.25.20_0.6-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"nouveau-kmp-debug-0.10.1.20081112_2.6.25.20_0.6-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"omnibook-kmp-debug-20080313_2.6.25.20_0.6-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"pcc-acpi-kmp-debug-0.9_2.6.25.20_0.6-4.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"pcfclock-kmp-debug-0.44_2.6.25.20_0.6-207.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tpctl-kmp-debug-4.17_2.6.25.20_0.6-189.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"uvcvideo-kmp-debug-r200_2.6.25.20_0.6-2.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"virtualbox-ose-kmp-debug-1.5.6_2.6.25.20_0.6-33.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"vmware-kmp-debug-2008.04.14_2.6.25.20_0.6-21.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"wlan-ng-kmp-debug-0.2.8_2.6.25.20_0.6-107.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acerhk-kmp-debug / acx-kmp-debug / appleir-kmp-debug / etc");
}

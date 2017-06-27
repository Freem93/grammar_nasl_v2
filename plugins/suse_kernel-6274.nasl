#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-6274.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39335);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2008-4554", "CVE-2008-5702", "CVE-2009-0028", "CVE-2009-0065", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0676", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-0859", "CVE-2009-1072", "CVE-2009-1265", "CVE-2009-1337", "CVE-2009-1439");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-6274)");
  script_summary(english:"Check for the kernel-6274 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for openSUSE 10.3 fixes some bugs and several
security problems.

The following security issues are fixed: A local denial of service
problem in the splice(2) system call.

CVE-2009-0834: The audit_syscall_entry function in the Linux kernel on
the x86_64 platform did not properly handle (1) a 32-bit process
making a 64-bit syscall or (2) a 64-bit process making a 32-bit
syscall, which allows local users to bypass certain syscall audit
configurations via crafted syscalls.

CVE-2009-1072: nfsd in the Linux kernel did not drop the CAP_MKNOD
capability before handling a user request in a thread, which allows
local users to create device nodes, as demonstrated on a filesystem
that has been exported with the root_squash option.

CVE-2009-0835 The __secure_computing function in kernel/seccomp.c in
the seccomp subsystem in the Linux kernel on the x86_64 platform, when
CONFIG_SECCOMP is enabled, does not properly handle (1) a 32-bit
process making a 64-bit syscall or (2) a 64-bit process making a
32-bit syscall, which allows local users to bypass intended access
restrictions via crafted syscalls that are misinterpreted as (a) stat
or (b) chmod.

CVE-2009-1439: Buffer overflow in fs/cifs/connect.c in CIFS in the
Linux kernel 2.6.29 and earlier allows remote attackers to cause a
denial of service (crash) or potential code execution via a long
nativeFileSystem field in a Tree Connect response to an SMB mount
request.

This requires that kernel can be made to mount a 'cifs' filesystem
from a malicious CIFS server.

CVE-2009-1337: The exit_notify function in kernel/exit.c in the Linux
kernel did not restrict exit signals when the CAP_KILL capability is
held, which allows local users to send an arbitrary signal to a
process by running a program that modifies the exit_signal field and
then uses an exec system call to launch a setuid application.

CVE-2009-0859: The shm_get_stat function in ipc/shm.c in the shm
subsystem in the Linux kernel, when CONFIG_SHMEM is disabled,
misinterprets the data type of an inode, which allows local users to
cause a denial of service (system hang) via an SHM_INFO shmctl call,
as demonstrated by running the ipcs program. (SUSE is enabling
CONFIG_SHMEM, so is by default not affected, the fix is just for
completeness).

CVE-2009-1265: Integer overflow in rose_sendmsg (sys/net/af_rose.c) in
the Linux kernel might allow attackers to obtain sensitive information
via a large length value, which causes 'garbage' memory to be sent.

CVE-2009-0028: The clone system call in the Linux kernel allows local
users to send arbitrary signals to a parent process from an
unprivileged child process by launching an additional child process
with the CLONE_PARENT flag, and then letting this new process exit.

CVE-2009-0676: The sock_getsockopt function in net/core/sock.c in the
Linux kernel does not initialize a certain structure member, which
allows local users to obtain potentially sensitive information from
kernel memory via an SO_BSDCOMPAT getsockopt request.

CVE-2009-0322: drivers/firmware/dell_rbu.c in the Linux kernel allows
local users to cause a denial of service (system crash) via a read
system call that specifies zero bytes from the (1) image_type or (2)
packet_size file in /sys/devices/platform/dell_rbu/.

CVE-2009-0269: fs/ecryptfs/inode.c in the eCryptfs subsystem in the
Linux kernel allows local users to cause a denial of service (fault or
memory corruption), or possibly have unspecified other impact, via a
readlink call that results in an error, leading to use of a -1 return
value as an array index.

CVE-2009-0065: Buffer overflow in net/sctp/sm_statefuns.c in the
Stream Control Transmission Protocol (sctp) implementation in the
Linux kernel allows remote attackers to have an unknown impact via an
FWD-TSN (aka FORWARD-TSN) chunk with a large stream ID.

CVE-2008-5702: Buffer underflow in the ibwdt_ioctl function in
drivers/watchdog/ib700wdt.c in the Linux kernel might allow local
users to have an unknown impact via a certain /dev/watchdog
WDIOC_SETTIMEOUT IOCTL call.

CVE-2008-4554: The do_splice_from function in fs/splice.c in the Linux
kernel does not reject file descriptors that have the O_APPEND flag
set, which allows local users to bypass append mode and make arbitrary
changes to other locations in the file.

Some other non-security bugs were fixed, please see the RPM changelog."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"kernel-bigsmp-2.6.22.19-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-debug-2.6.22.19-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-default-2.6.22.19-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-source-2.6.22.19-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-syms-2.6.22.19-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xen-2.6.22.19-0.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xenpae-2.6.22.19-0.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-debug / kernel-default / kernel-source / etc");
}

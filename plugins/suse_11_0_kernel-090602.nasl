#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-951.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40012);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2009-0028", "CVE-2009-0065", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-0859", "CVE-2009-1072", "CVE-2009-1242", "CVE-2009-1265", "CVE-2009-1337", "CVE-2009-1439", "CVE-2009-1630");

  script_name(english:"openSUSE Security Update : kernel (kernel-951)");
  script_summary(english:"Check for the kernel-951 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for openSUSE 11.0 fixes some bugs and several
security problems.

The following security issues are fixed: A local denial of service
problem in the splice(2) system call.

CVE-2009-1630: The nfs_permission function in fs/nfs/dir.c in the NFS
client implementation in the Linux kernel when atomic_open is
available, does not check execute (aka EXEC or MAY_EXEC) permission
bits, which allows local users to bypass permissions and execute
files, as demonstrated by files on an NFSv4 fileserver.

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

CVE-2009-1242: The vmx_set_msr function in arch/x86/kvm/vmx.c in the
VMX implementation in the KVM subsystem in the Linux kernel on the
i386 platform allows guest OS users to cause a denial of service
(OOPS) by setting the EFER_LME (aka 'Long mode enable') bit in the
Extended Feature Enable Register (EFER) model-specific register, which
is specific to the x86_64 platform.

CVE-2009-1265: Integer overflow in rose_sendmsg (sys/net/af_rose.c) in
the Linux kernel might allow attackers to obtain sensitive information
via a large length value, which causes 'garbage' memory to be sent.

CVE-2009-0028: The clone system call in the Linux kernel allows local
users to send arbitrary signals to a parent process from an
unprivileged child process by launching an additional child process
with the CLONE_PARENT flag, and then letting this new process exit.

CVE-2009-0675: The skfp_ioctl function in drivers/net/skfp/skfddi.c in
the Linux kernel permits SKFP_CLR_STATS requests only when the
CAP_NET_ADMIN capability is absent, instead of when this capability is
present, which allows local users to reset the driver statistics,
related to an 'inverted logic' issue.

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

Some other non-security bugs were fixed, please see the RPM changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=399966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=407523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=408818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=429484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=462365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=463522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=465955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=465963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=470942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=470943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=472896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=478002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=478003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=482720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=483819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=483820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=487106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=487681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=490608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=495065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=496398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=497551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=497597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=498237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=502675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=503353"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 20, 119, 189, 264, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"acerhk-kmp-debug-0.5.35_2.6.25.20_0.4-98.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"acx-kmp-debug-20080210_2.6.25.20_0.4-3.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"appleir-kmp-debug-1.1_2.6.25.20_0.4-108.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"at76_usb-kmp-debug-0.17_2.6.25.20_0.4-2.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"atl2-kmp-debug-2.0.4_2.6.25.20_0.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"aufs-kmp-debug-cvs20080429_2.6.25.20_0.4-13.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"dazuko-kmp-debug-2.3.4.4_2.6.25.20_0.4-42.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"drbd-kmp-debug-8.2.6_2.6.25.20_0.4-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"gspcav-kmp-debug-01.00.20_2.6.25.20_0.4-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"iscsitarget-kmp-debug-0.4.15_2.6.25.20_0.4-63.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ivtv-kmp-debug-1.0.3_2.6.25.20_0.4-66.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-debug-2.6.25.20-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-default-2.6.25.20-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-pae-2.6.25.20-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-source-2.6.25.20-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-syms-2.6.25.20-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-vanilla-2.6.25.20-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-xen-2.6.25.20-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kqemu-kmp-debug-1.3.0pre11_2.6.25.20_0.4-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"nouveau-kmp-debug-0.10.1.20081112_2.6.25.20_0.4-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"omnibook-kmp-debug-20080313_2.6.25.20_0.4-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"pcc-acpi-kmp-debug-0.9_2.6.25.20_0.4-4.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"pcfclock-kmp-debug-0.44_2.6.25.20_0.4-207.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tpctl-kmp-debug-4.17_2.6.25.20_0.4-189.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"uvcvideo-kmp-debug-r200_2.6.25.20_0.4-2.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"virtualbox-ose-kmp-debug-1.5.6_2.6.25.20_0.4-33.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"vmware-kmp-debug-2008.04.14_2.6.25.20_0.4-21.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"wlan-ng-kmp-debug-0.2.8_2.6.25.20_0.4-107.1") ) flag++;

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

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-478.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76988);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/25 14:45:37 $");

  script_cve_id("CVE-2014-0131", "CVE-2014-2309", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3917", "CVE-2014-4014", "CVE-2014-4171", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2014:0957-1)");
  script_summary(english:"Check for the openSUSE-2014-478 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Linux Kernel was updated to fix various bugs and security issues.

CVE-2014-4699: The Linux kernel on Intel processors did not properly
restrict use of a non-canonical value for the saved RIP address in the
case of a system call that does not use IRET, which allowed local
users to leverage a race condition and gain privileges, or cause a
denial of service (double fault), via a crafted application that makes
ptrace and fork system calls.

CVE-2014-4667: The sctp_association_free function in
net/sctp/associola.c in the Linux kernel did not properly manage a
certain backlog value, which allowed remote attackers to cause a
denial of service (socket outage) via a crafted SCTP packet.

CVE-2014-4171: mm/shmem.c in the Linux kernel did not properly
implement the interaction between range notification and hole
punching, which allowed local users to cause a denial of service
(i_mutex hold) by using the mmap system call to access a hole, as
demonstrated by interfering with intended shmem activity by blocking
completion of (1) an MADV_REMOVE madvise call or (2) an
FALLOC_FL_PUNCH_HOLE fallocate call.

CVE-2014-4508: arch/x86/kernel/entry_32.S in the Linux kernel on
32-bit x86 platforms, when syscall auditing is enabled and the sep CPU
feature flag is set, allowed local users to cause a denial of service
(OOPS and system crash) via an invalid syscall number, as demonstrated
by number 1000.

CVE-2014-4656: Multiple integer overflows in sound/core/control.c in
the ALSA control implementation in the Linux kernel allowed local
users to cause a denial of service by leveraging /dev/snd/controlCX
access, related to (1) index values in the snd_ctl_add function and
(2) numid values in the snd_ctl_remove_numid_conflict function.

CVE-2014-4655: The snd_ctl_elem_add function in sound/core/control.c
in the ALSA control implementation in the Linux kernel did not
properly maintain the user_ctl_count value, which allowed local users
to cause a denial of service (integer overflow and limit bypass) by
leveraging /dev/snd/controlCX access for a large number of
SNDRV_CTL_IOCTL_ELEM_REPLACE ioctl calls.

CVE-2014-4654: The snd_ctl_elem_add function in sound/core/control.c
in the ALSA control implementation in the Linux kernel did not check
authorization for SNDRV_CTL_IOCTL_ELEM_REPLACE commands, which allowed
local users to remove kernel controls and cause a denial of service
(use-after-free and system crash) by leveraging /dev/snd/controlCX
access for an ioctl call.

CVE-2014-4653: sound/core/control.c in the ALSA control implementation
in the Linux kernel did not ensure possession of a read/write lock,
which allowed local users to cause a denial of service
(use-after-free) and obtain sensitive information from kernel memory
by leveraging /dev/snd/controlCX access.

CVE-2014-4652: Race condition in the tlv handler functionality in the
snd_ctl_elem_user_tlv function in sound/core/control.c in the ALSA
control implementation in the Linux kernel allowed local users to
obtain sensitive information from kernel memory by leveraging
/dev/snd/controlCX access.

CVE-2014-4014: The capabilities implementation in the Linux kernel did
not properly consider that namespaces are inapplicable to inodes,
which allowed local users to bypass intended chmod restrictions by
first creating a user namespace, as demonstrated by setting the setgid
bit on a file with group ownership of root.

CVE-2014-2309: The ip6_route_add function in net/ipv6/route.c in the
Linux kernel did not properly count the addition of routes, which
allowed remote attackers to cause a denial of service (memory
consumption) via a flood of ICMPv6 Router Advertisement packets.

CVE-2014-3917: kernel/auditsc.c in the Linux kernel, when
CONFIG_AUDITSYSCALL is enabled with certain syscall rules, allowed
local users to obtain potentially sensitive single-bit values from
kernel memory or cause a denial of service (OOPS) via a large value of
a syscall number.

CVE-2014-0131: Use-after-free vulnerability in the skb_segment
function in net/core/skbuff.c in the Linux kernel allowed attackers to
obtain sensitive information from kernel memory by leveraging the
absence of a certain orphaning operation.

CVE-2014-3144: The (1) BPF_S_ANC_NLATTR and (2) BPF_S_ANC_NLATTR_NEST
extension implementations in the sk_run_filter function in
net/core/filter.c in the Linux kernel did not check whether a certain
length value is sufficiently large, which allowed local users to cause
a denial of service (integer underflow and system crash) via crafted
BPF instructions.

CVE-2014-3145: The BPF_S_ANC_NLATTR_NEST extension implementation in
the sk_run_filter function in net/core/filter.c in the Linux kernel
used the reverse order in a certain subtraction, which allowed local
users to cause a denial of service (over-read and system crash) via
crafted BPF instructions. NOTE: the affected code was moved to the
__skb_get_nlattr_nest function before the vulnerability was announced.

Additional Bug fixed :

  - HID: logitech-dj: Fix USB 3.0 issue (bnc#788080)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=788080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=877257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=882189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=885422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=885725"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-source-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-source-vanilla-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-syms-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-devel-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-base-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-debugsource-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-devel-3.7.10-1.40.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-devel-debuginfo-3.7.10-1.40.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}

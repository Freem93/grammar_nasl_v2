#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-176.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74914);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/14 00:08:46 $");

  script_cve_id("CVE-2012-0957", "CVE-2012-2745", "CVE-2012-3375", "CVE-2012-3400", "CVE-2012-3412", "CVE-2012-4508", "CVE-2012-4530", "CVE-2012-5374", "CVE-2013-0160", "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0309", "CVE-2013-0871");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2013:0396-1)");
  script_summary(english:"Check for the openSUSE-2013-176 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Linux kernel was updated to fix various bugs and security issues :

CVE-2013-0871: Race condition in the ptrace functionality in the Linux
kernel allowed local users to gain privileges via a PTRACE_SETREGS
ptrace system call in a crafted application, as demonstrated by
ptrace_death.

CVE-2013-0160: Avoid a side channel attack on /dev/ptmx (keyboard
input timing).

CVE-2012-5374: Fixed a local denial of service in the BTRFS hashing
code.

CVE-2013-0309: arch/x86/include/asm/pgtable.h in the Linux kernel,
when transparent huge pages are used, does not properly support
PROT_NONE memory regions, which allows local users to cause a denial
of service (system crash) via a crafted application.

CVE-2013-0268: The msr_open function in arch/x86/kernel/msr.c in the
Linux kernel allowed local users to bypass intended capability
restrictions by executing a crafted application as root, as
demonstrated by msr32.c.

CVE-2012-0957: The override_release function in kernel/sys.c in the
Linux kernel allowed local users to obtain sensitive information from
kernel stack memory via a uname system call in conjunction with a
UNAME26 personality.

CVE-2013-0216: The Xen netback functionality in the Linux kernel
allowed guest OS users to cause a denial of service (loop) by
triggering ring pointer corruption.

CVE-2013-0231: The pciback_enable_msi function in the PCI backend
driver (drivers/xen/pciback/conf_space_capability_msi.c) in Xen for
the Linux kernel allowed guest OS users with PCI device access to
cause a denial of service via a large number of kernel log messages.
NOTE: some of these details are obtained from third-party information.

CVE-2012-4530: The load_script function in fs/binfmt_script.c in the
Linux kernel did not properly handle recursion, which allowed local
users to obtain sensitive information from kernel stack memory via a
crafted application.

CVE-2012-4508: Race condition in fs/ext4/extents.c in the Linux kernel
allowed local users to obtain sensitive information from a deleted
file by reading an extent that was not properly marked as
uninitialized.

CVE-2012-3412: The sfc (aka Solarflare Solarstorm) driver in the Linux
kernel allowed remote attackers to cause a denial of service (DMA
descriptor consumption and network-controller outage) via crafted TCP
packets that trigger a small MSS value.

CVE-2012-2745: The copy_creds function in kernel/cred.c in the Linux
kernel provided an invalid replacement session keyring to a child
process, which allowed local users to cause a denial of service
(panic) via a crafted application that uses the fork system call.

CVE-2012-3375: The epoll_ctl system call in fs/eventpoll.c in the
Linux kernel did not properly handle ELOOP errors in EPOLL_CTL_ADD
operations, which allowed local users to cause a denial of service
(file-descriptor consumption and system crash) via a crafted
application that attempts to create a circular epoll dependency.

CVE-2012-3400: Heap-based buffer overflow in the udf_load_logicalvol
function in fs/udf/super.c in the Linux kernel allowed remote
attackers to cause a denial of service (system crash) or possibly have
unspecified other impact via a crafted UDF filesystem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=720226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=781134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=784192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804738"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-base-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-base-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-debugsource-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-devel-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-devel-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-base-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-base-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-debugsource-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-devel-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-devel-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-base-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-base-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-debugsource-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-devel-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-devel-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-devel-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-base-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-base-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-debugsource-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-devel-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-devel-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-extra-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-extra-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-base-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-base-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-debugsource-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-devel-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-devel-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-source-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-source-vanilla-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-syms-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-base-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-base-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-debugsource-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-devel-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-devel-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-base-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-base-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-debugsource-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-devel-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-devel-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-base-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-base-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-debuginfo-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-debugsource-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-devel-3.1.10-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-devel-debuginfo-3.1.10-1.19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}

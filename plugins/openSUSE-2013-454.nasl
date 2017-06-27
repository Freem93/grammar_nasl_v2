#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-454.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75018);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-0913", "CVE-2013-1767", "CVE-2013-1774", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1928", "CVE-2013-2094");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2013:0847-1)");
  script_summary(english:"Check for the openSUSE-2013-454 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 12.1 kernel was updated to fix a severe secrutiy issue
and various bugs.

Security issues fixed: CVE-2013-2094: The perf_swevent_init function
in kernel/events/core.c in the Linux kernel used an incorrect integer
data type, which allowed local users to gain privileges via a crafted
perf_event_open system call.

CVE-2013-1774: The chase_port function in drivers/usb/serial/io_ti.c
in the Linux kernel allowed local users to cause a denial of service
(NULL pointer dereference and system crash) via an attempted
/dev/ttyUSB read or write operation on a disconnected Edgeport USB
serial converter.

CVE-2013-1928: The do_video_set_spu_palette function in
fs/compat_ioctl.c in the Linux kernel lacked a certain error check,
which might have allowed local users to obtain sensitive information
from kernel stack memory via a crafted VIDEO_SET_SPU_PALETTE ioctl
call on a /dev/dvb device.

CVE-2013-1796: The kvm_set_msr_common function in arch/x86/kvm/x86.c
in the Linux kernel did not ensure a required time_page alignment
during an MSR_KVM_SYSTEM_TIME operation, which allowed guest OS users
to cause a denial of service (buffer overflow and host OS memory
corruption) or possibly have unspecified other impact via a crafted
application.

CVE-2013-1797: Use-after-free vulnerability in arch/x86/kvm/x86.c in
the Linux kernel allowed guest OS users to cause a denial of service
(host OS memory corruption) or possibly have unspecified other impact
via a crafted application that triggers use of a guest physical
address (GPA) in (1) movable or (2) removable memory during an
MSR_KVM_SYSTEM_TIME kvm_set_msr_common operation.

CVE-2013-1798: The ioapic_read_indirect function in virt/kvm/ioapic.c
in the Linux kernel did not properly handle a certain combination of
invalid IOAPIC_REG_SELECT and IOAPIC_REG_WINDOW operations, which
allowed guest OS users to obtain sensitive information from host OS
memory or cause a denial of service (host OS OOPS) via a crafted
application.

CVE-2013-1767: Use-after-free vulnerability in the shmem_remount_fs
function in mm/shmem.c in the Linux kernel allowed local users to gain
privileges or cause a denial of service (system crash) by remounting a
tmpfs filesystem without specifying a required mpol (aka mempolicy)
mount option.

CVE-2013-0913: Integer overflow in
drivers/gpu/drm/i915/i915_gem_execbuffer.c in the i915 driver in the
Direct Rendering Manager (DRM) subsystem in the Linux kernel allowed
local users to cause a denial of service (heap-based buffer overflow)
or possibly have unspecified other impact via a crafted application
that triggers many relocation copies, and potentially leads to a race
condition.

Bugs fixed :

  - qlge: fix dma map leak when the last chunk is not
    allocated (bnc#819519).

  - TTY: fix atime/mtime regression (bnc#815745).

  - fs/compat_ioctl.c: VIDEO_SET_SPU_PALETTE missing error
    check (bnc#813735).

  - USB: io_ti: Fix NULL dereference in chase_port()
    (bnc#806976, CVE-2013-1774).

  - KVM: Convert MSR_KVM_SYSTEM_TIME to use
    gfn_to_hva_cache_init (bnc#806980 CVE-2013-1797).

  - KVM: Fix bounds checking in ioapic indirect register
    read (bnc#806980 CVE-2013-1798).

  - KVM: Fix for buffer overflow in handling of
    MSR_KVM_SYSTEM_TIME (bnc#806980 CVE-2013-1796).

  - kabi/severities: Allow kvm module abi changes - modules
    are self consistent

  - loopdev: fix a deadlock (bnc#809748).

  - block: use i_size_write() in bd_set_size() (bnc#809748).

  - drm/i915: bounds check execbuffer relocation count
    (bnc#808829,CVE-2013-0913).

  - tmpfs: fix use-after-free of mempolicy object
    (bnc#806138, CVE-2013-1767)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-05/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819789"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/23");
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

if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-base-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-base-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-debugsource-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-devel-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-devel-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-base-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-base-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-debugsource-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-devel-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-devel-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-base-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-base-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-debugsource-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-devel-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-devel-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-devel-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-base-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-base-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-debugsource-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-devel-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-devel-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-extra-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-extra-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-base-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-base-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-debugsource-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-devel-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-devel-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-source-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-source-vanilla-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-syms-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-base-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-base-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-debugsource-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-devel-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-devel-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-base-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-base-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-debugsource-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-devel-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-devel-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-base-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-base-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-debugsource-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-devel-3.1.10-1.23.1.g8645a72") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-devel-debuginfo-3.1.10-1.23.1.g8645a72") ) flag++;

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

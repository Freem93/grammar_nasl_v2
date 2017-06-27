#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-452.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75016);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2013-0290", "CVE-2013-2094");
  script_bugtraq_id(57964, 59846);

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2013:0951-1)");
  script_summary(english:"Check for the openSUSE-2013-452 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 12.3 kernel was updated to fix a critical security issue,
other security issues and several bugs.

Security issues fixed: CVE-2013-2094: The perf_swevent_init function
in kernel/events/core.c in the Linux kernel used an incorrect integer
data type, which allowed local users to gain privileges via a crafted
perf_event_open system call.

CVE-2013-0290: The __skb_recv_datagram function in net/core/datagram.c
in the Linux kernel did not properly handle the MSG_PEEK flag with
zero-length data, which allowed local users to cause a denial of
service (infinite loop and system hang) via a crafted application.

Bugs fixed :

  - qlge: fix dma map leak when the last chunk is not
    allocated (bnc#819519).

  - ACPI / thermal: do not always return
    THERMAL_TREND_RAISING for active trip points
    (bnc#820048).

  - perf: Treat attr.config as u64 in perf_swevent_init()
    (bnc#819789, CVE-2013-2094).

  - cxgb4: fix error recovery when t4_fw_hello returns a
    positive value (bnc#818497).

  - kabi/severities: Ignore drivers/mfd/ucb1400_core It
    provides internal exports to UCB1400 drivers, that we
    have just disabled.

  - Fix -devel package for armv7hl armv7hl kernel flavors in
    the non-multiplatform configuration (which is the
    default for our openSUSE 12.3 release), needs more
    header files from the machine specific directories to be
    included in kernel-devel.

  - Update config files: disable UCB1400 on all but ARM
    Currently UCB1400 is only used on ARM OMAP systems, and
    part of the code is dead code that can't even be
    modularized.

  - CONFIG_UCB1400_CORE=n

  - CONFIG_TOUCHSCREEN_UCB1400=n

  - CONFIG_GPIO_UCB1400=n

  - rpm/config.sh: Drop the ARM repository, the KOTD will
    build against the 'ports' repository of openSUSE:12.3

  - mm/mmap: check for RLIMIT_AS before unmapping
    (bnc#818327).

  - rpm/kernel-spec-macros: Properly handle KOTD release
    numbers with .g<commit> suffix

  - rpm/kernel-spec-macros: Drop the %release_num macro We
    no longer put the -rcX tag into the release string.

  - xen-pciback: notify hypervisor about devices intended to
    be assigned to guests.

  - unix/stream: fix peeking with an offset larger than data
    in queue (bnc#803931 CVE-2013-0290).

  - unix/dgram: fix peeking with an offset larger than data
    in queue (bnc#803931 CVE-2013-0290).

  - unix/dgram: peek beyond 0-sized skbs (bnc#803931
    CVE-2013-0290).

  - net: fix infinite loop in __skb_recv_datagram()
    (bnc#803931 CVE-2013-0290).

  - TTY: fix atime/mtime regression (bnc#815745).

  - md/raid1,raid10: fix deadlock with freeze_array()
    (813889).

  - md: raid1,10: Handle REQ_WRITE_SAME flag in write bios
    (bnc#813889).

  - KMS: fix EDID detailed timing vsync parsing.

  - KMS: fix EDID detailed timing frame rate.

  - Add Netfilter/ebtables support Those modues are needed
    for proper OpenStack support on ARM, and are also
    enabled on x86(_64)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00087.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818497"
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
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820048"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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

if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-source-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-source-vanilla-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-syms-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-devel-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-base-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-debugsource-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-devel-3.7.10-1.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-devel-debuginfo-3.7.10-1.11.1") ) flag++;

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

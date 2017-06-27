#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-235.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74604);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-1083", "CVE-2011-4077", "CVE-2011-4086", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-1146");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2012:0540-1)");
  script_summary(english:"Check for the openSUSE-2012-235 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes various bugs and security issues.

For bugfixes,

  - a lot of BTRFS bugs were fixed

  - a performance issue with transparent huge pages was
    fixed which could have caused huge slowdowns when doing
    I/O over e.g. USB sticks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-04/msg00047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=676204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=718918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=719416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=721739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=722350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=729247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755812"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
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

if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-base-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-base-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-debugsource-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-devel-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-debug-devel-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-base-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-base-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-debugsource-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-devel-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-default-devel-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-base-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-base-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-debugsource-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-devel-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-desktop-devel-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-devel-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-base-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-base-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-debugsource-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-devel-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-devel-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-extra-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-ec2-extra-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-base-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-base-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-debugsource-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-devel-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-pae-devel-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-source-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-source-vanilla-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-syms-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-base-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-base-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-debugsource-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-devel-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-trace-devel-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-base-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-base-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-debugsource-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-devel-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-vanilla-devel-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-base-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-base-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-debuginfo-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-debugsource-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-devel-3.1.10-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"kernel-xen-devel-debuginfo-3.1.10-1.9.1") ) flag++;

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

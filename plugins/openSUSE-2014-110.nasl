#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-110.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75248);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/12/14 06:22:31 $");

  script_cve_id("CVE-2014-0591");

  script_name(english:"openSUSE Security Update : bind (openSUSE-SU-2014:0199-1)");
  script_summary(english:"Check for the openSUSE-2014-110 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to version 9.9.4P2

  - Fixes named crash when handling malformed NSEC3-signed
    zones (CVE-2014-0591, bnc#858639)

  - Obsoletes workaround-compile-problem.diff

  - Replace rpz2+rl-9.9.3-P1.patch by rpz2-9.9.4.patch, rl
    is now supported upstream (--enable-rrl)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858639"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-lwresd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-lwresd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/27");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"bind-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bind-chrootenv-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bind-debuginfo-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bind-debugsource-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bind-devel-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bind-libs-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bind-libs-debuginfo-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bind-lwresd-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bind-lwresd-debuginfo-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bind-utils-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"bind-utils-debuginfo-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"bind-libs-32bit-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"bind-libs-debuginfo-32bit-9.9.4P2-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-chrootenv-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-debuginfo-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-debugsource-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-devel-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-libs-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-libs-debuginfo-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-lwresd-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-lwresd-debuginfo-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-utils-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"bind-utils-debuginfo-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"bind-libs-32bit-9.9.4P2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"bind-libs-debuginfo-32bit-9.9.4P2-2.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chrootenv / bind-debuginfo / bind-debugsource / etc");
}

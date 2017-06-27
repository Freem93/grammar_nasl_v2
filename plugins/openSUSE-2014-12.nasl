#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-12.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75255);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_name(english:"openSUSE Security Update : acroread (openSUSE-SU-2014:0006-1)");
  script_summary(english:"Check for the openSUSE-2014-12 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adobe discontinued the Adobe Reader 9 for Linux in June 2013 and has
not fixed and will not fix any further security issues in it.

As there is no new version, it is officially out of support.

The SUSE Security Team strongly recommends to not use it anymore.

Installing this update will deinstall the plugin package to avoid
automatic exploitation via PDF embedded in webpages or emails."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843835"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected acroread packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-cmaps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/27");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"acroread-9.5.5-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-cmaps-9.4.1-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-fonts-ja-9.4.1-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-fonts-ko-9.4.1-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-fonts-zh_CN-9.4.1-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"acroread-fonts-zh_TW-9.4.1-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-9.5.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-cmaps-9.4.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-fonts-ja-9.4.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-fonts-ko-9.4.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-fonts-zh_CN-9.4.1-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"acroread-fonts-zh_TW-9.4.1-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acroread");
}

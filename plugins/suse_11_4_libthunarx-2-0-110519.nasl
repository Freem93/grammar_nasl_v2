#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libthunarx-2-0-4590.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75924);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-1588");

  script_name(english:"openSUSE Security Update : libthunarx-2-0 (openSUSE-SU-2011:0518-1)");
  script_summary(english:"Check for the libthunarx-2-0-4590 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Due to a format string error thunar could crash when copy&pasting a
file name with format characters (CVE-2011-1588)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-05/msg00047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=687874"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libthunarx-2-0 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libthunarx-2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libthunarx-2-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:thunar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:thunar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:thunar-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:thunar-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:thunar-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"libthunarx-2-0-1.3.0-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libthunarx-2-0-debuginfo-1.3.0-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"thunar-1.3.0-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"thunar-debuginfo-1.3.0-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"thunar-debugsource-1.3.0-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"thunar-devel-1.3.0-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"thunar-lang-1.3.0-1.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libthunarx-2-0 / thunar / thunar-devel / thunar-lang / etc");
}

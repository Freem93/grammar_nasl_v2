#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kdelibs3-1648.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(43053);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 19:49:34 $");

  script_name(english:"openSUSE Security Update : kdelibs3 (kdelibs3-1648)");
  script_summary(english:"Check for the kdelibs3-1648 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KDE KDELibs Remote Array Overrun (Arbitrary code execution),
CVE-2009-0689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557126"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs3 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3-arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3-arts-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3-default-style");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3-default-style-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:utempter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:utempter-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"kdelibs3-3.5.10-21.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdelibs3-arts-3.5.10-21.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdelibs3-default-style-3.5.10-21.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdelibs3-devel-3.5.10-21.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdelibs4-4.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kdelibs4-core-4.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkde4-4.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkde4-devel-4.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkdecore4-4.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libkdecore4-devel-4.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"utempter-0.5.5-105.46") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"kdelibs3-32bit-3.5.10-21.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"kdelibs3-arts-32bit-3.5.10-21.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"kdelibs3-default-style-32bit-3.5.10-21.12.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libkde4-32bit-4.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"libkdecore4-32bit-4.1.3-4.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"utempter-0.5.5-105.50") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"utempter-32bit-0.5.5-105.46") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs3 / kdelibs4");
}

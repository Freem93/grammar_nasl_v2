#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1499.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95975);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id("CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843");

  script_name(english:"openSUSE Security Update : zlib (openSUSE-2016-1499)");
  script_summary(english:"Check for the openSUSE-2016-1499 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for zlib fixes the following issues :

  - Remove incompatible declarations of 'struct
    internal_state' (boo#1003577)

  - Avoid out-of-bounds pointer arithmetic in inftrees.c
    (boo#1003579, CVE-2016-9840, CVE-2016-9841)

  - Avoid left-shift with negative number (boo#1003580,
    CVE-2016-9842)

  - Avoid undefined behaviour in pointer arithmetic on
    powerpc (boo#1013882, CVE-2016-9843)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013882"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected zlib packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libminizip1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libminizip1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libz1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libz1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libz1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libz1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:minizip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zlib-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zlib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zlib-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zlib-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zlib-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libminizip1-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libminizip1-debuginfo-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libz1-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libz1-debuginfo-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"minizip-devel-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"zlib-debugsource-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"zlib-devel-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"zlib-devel-static-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libz1-32bit-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libz1-debuginfo-32bit-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"zlib-devel-32bit-1.2.8-5.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"zlib-devel-static-32bit-1.2.8-5.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libminizip1 / libminizip1-debuginfo / libz1 / libz1-32bit / etc");
}

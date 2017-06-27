#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-575.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100202);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/16 13:59:27 $");

  script_cve_id("CVE-2017-8422");

  script_name(english:"openSUSE Security Update : kauth / kdelibs4 (openSUSE-2017-575)");
  script_summary(english:"Check for the openSUSE-2017-575 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kauth and kdelibs4 fixes the following issues :

  - CVE-2017-8422: logic flaw in the KAuth framework allowed
    privilege escalation (boo#1036244)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036244"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kauth / kdelibs4 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kauth-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kauth-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kauth-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs4-doc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5Auth5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5Auth5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5Auth5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5Auth5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libKF5Auth5-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkde4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libkdecore4-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libksuseinstall1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"kauth-debugsource-5.21.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kauth-devel-5.21.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-apidocs-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-branding-upstream-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-core-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-core-debuginfo-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-debuginfo-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-debugsource-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kdelibs4-doc-debuginfo-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libKF5Auth5-5.21.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libKF5Auth5-debuginfo-5.21.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libKF5Auth5-lang-5.21.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkde4-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkde4-debuginfo-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkde4-devel-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkdecore4-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkdecore4-debuginfo-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkdecore4-devel-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libkdecore4-devel-debuginfo-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libksuseinstall-devel-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libksuseinstall1-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libksuseinstall1-debuginfo-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kauth-devel-32bit-5.21.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libKF5Auth5-32bit-5.21.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libKF5Auth5-debuginfo-32bit-5.21.0-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libkde4-32bit-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libkde4-debuginfo-32bit-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libkdecore4-32bit-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libkdecore4-debuginfo-32bit-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libksuseinstall1-32bit-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libksuseinstall1-debuginfo-32bit-4.14.18-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kauth-debugsource-5.26.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kauth-devel-5.26.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-apidocs-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-branding-upstream-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-core-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-core-debuginfo-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-debuginfo-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-debugsource-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kdelibs4-doc-debuginfo-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libKF5Auth5-5.26.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libKF5Auth5-debuginfo-5.26.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libKF5Auth5-lang-5.26.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkde4-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkde4-debuginfo-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkde4-devel-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkdecore4-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkdecore4-debuginfo-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkdecore4-devel-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libkdecore4-devel-debuginfo-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libksuseinstall-devel-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libksuseinstall1-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libksuseinstall1-debuginfo-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"kauth-devel-32bit-5.26.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libKF5Auth5-32bit-5.26.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libKF5Auth5-debuginfo-32bit-5.26.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libkde4-32bit-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libkde4-debuginfo-32bit-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libkdecore4-32bit-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libkdecore4-debuginfo-32bit-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libksuseinstall1-32bit-4.14.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libksuseinstall1-debuginfo-32bit-4.14.25-7.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kauth-debugsource / kauth-devel-32bit / kauth-devel / etc");
}

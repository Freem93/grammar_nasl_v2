#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1041.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93249);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2016-6318");

  script_name(english:"openSUSE Security Update : cracklib (openSUSE-2016-1041)");
  script_summary(english:"Check for the openSUSE-2016-1041 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cracklib fixes the following issues :

  - Add patch to fix a buffer overflow in GECOS parser
    (bsc#992966 CVE-2016-6318)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992966"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cracklib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cracklib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cracklib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cracklib-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cracklib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cracklib-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cracklib-dict-small");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrack2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrack2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrack2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrack2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpwquality-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpwquality-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpwquality-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpwquality-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpwquality-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpwquality1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpwquality1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_pwquality");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pam_pwquality-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-pwquality");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-pwquality-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/01");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"cracklib-2.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"cracklib-debuginfo-2.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"cracklib-debugsource-2.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"cracklib-devel-2.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"cracklib-dict-small-2.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcrack2-2.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libcrack2-debuginfo-2.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpwquality-debugsource-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpwquality-devel-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpwquality-lang-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpwquality-tools-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpwquality-tools-debuginfo-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpwquality1-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpwquality1-debuginfo-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pam_pwquality-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pam_pwquality-debuginfo-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-pwquality-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python-pwquality-debuginfo-1.2.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"cracklib-devel-32bit-2.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcrack2-32bit-2.9.0-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libcrack2-debuginfo-32bit-2.9.0-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cracklib / cracklib-debuginfo / cracklib-debugsource / etc");
}

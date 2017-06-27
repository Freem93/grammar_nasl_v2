#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1277.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94664);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/10 14:37:36 $");

  script_cve_id("CVE-2016-5180");

  script_name(english:"openSUSE Security Update : nodejs (openSUSE-2016-1277)");
  script_summary(english:"Check for the openSUSE-2016-1277 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nodejs fixes the following issues :

  - New upstream LTS version 4.6.1

  - c-ares :

  + CVE-2016-5180: fix for single-byte buffer overwrite

  - Fix nodejs-libpath.patch so ppc doesn't fail to build"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"nodejs-4.6.1-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-debuginfo-4.6.1-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-debugsource-4.6.1-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"nodejs-devel-4.6.1-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-4.6.1-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-debuginfo-4.6.1-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-debugsource-4.6.1-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"nodejs-devel-4.6.1-36.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"npm-4.6.1-36.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs / nodejs-debuginfo / nodejs-debugsource / nodejs-devel / npm");
}

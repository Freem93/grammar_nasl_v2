#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-209.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97006);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/06 15:09:25 $");

  script_cve_id("CVE-2016-2037");

  script_name(english:"openSUSE Security Update : cpio (openSUSE-2017-209)");
  script_summary(english:"Check for the openSUSE-2017-209 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cpio fixes two issues.

This security issue was fixed :

  - CVE-2016-2037: The cpio_safer_name_suffix function in
    util.c in cpio allowed remote attackers to cause a
    denial of service (out-of-bounds write) via a crafted
    cpio file (bsc#963448).

This non-security issue was fixed :

  - bsc#1020108: Always use 32 bit CRC to prevent checksum
    errors for files greater than 32MB

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963448"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cpio packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpio-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpio-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cpio-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/06");
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

if ( rpm_check(release:"SUSE42.1", reference:"cpio-2.11-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"cpio-debuginfo-2.11-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"cpio-debugsource-2.11-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"cpio-lang-2.11-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cpio-2.11-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cpio-debuginfo-2.11-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cpio-debugsource-2.11-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"cpio-lang-2.11-33.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpio / cpio-debuginfo / cpio-debugsource / cpio-lang");
}

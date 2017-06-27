#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1207.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94217);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/03/13 15:28:56 $");

  script_cve_id("CVE-2013-5653", "CVE-2016-7978", "CVE-2016-7979");

  script_name(english:"openSUSE Security Update : ghostscript-library (openSUSE-2016-1207)");
  script_summary(english:"Check for the openSUSE-2016-1207 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ghostscript-library fixes the following issues :

  - Multiple security vulnerabilities have been discovered
    where ghostscript's '-dsafer' flag did not provide
    sufficient protection against unintended access to the
    file system. Thus, a machine that would process a
    specially crafted Postscript file would potentially leak
    sensitive information to an attacker. (CVE-2013-5653,
    bsc#1001951)

  - An incorrect reference count was found in .setdevice.
    This issue lead to a use-after-free scenario, which
    could have been exploited for denial-of-service or,
    possibly, arbitrary code execution attacks.
    (CVE-2016-7978, bsc#1001951)

  - Insufficient validation of the type of input in
    .initialize_dsc_parser used to allow remote code
    execution. (CVE-2016-7979, bsc#1001951)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001951"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript-library packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-9.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-debuginfo-9.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-debugsource-9.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-devel-9.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-mini-9.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-mini-debuginfo-9.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-mini-debugsource-9.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-mini-devel-9.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-x11-9.15-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ghostscript-x11-debuginfo-9.15-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript-mini / ghostscript-mini-debuginfo / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-262.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97282);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2016-10128", "CVE-2016-10129", "CVE-2016-10130", "CVE-2017-5338", "CVE-2017-5339");

  script_name(english:"openSUSE Security Update : libgit2 (openSUSE-2017-262)");
  script_summary(english:"Check for the openSUSE-2017-262 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libgit2 fixes the several issues.

These security issues were fixed :

  - CVE-2016-10128: Additional sanitization prevent some
    edge cases in the Git Smart Protocol which can lead to
    reading outside of a buffer (bsc#1019036).

  - CVE-2016-10129: Additional sanitization prevent some
    edge cases in the Git Smart Protocol which can lead to
    reading outside of a buffer (bsc#1019036).

  - CVE-2016-10130: When using the custom certificate
    callback or when using pygit2 or git2go a attacker could
    have caused an invalid certificate to be accepted
    (bsc#1019037).

  - CVE-2017-5338: When using the custom certificate
    callback or when using pygit2 or git2go a attacker could
    have caused an invalid certificate to be accepted
    (bsc#1019037).

  - CVE-2017-5339: When using the custom certificate
    callback or when using pygit2 or git2go a attacker could
    have caused an invalid certificate to be accepted
    (bsc#1019037).

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019037"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgit2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-24-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-24-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libgit2-24-0.24.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgit2-24-debuginfo-0.24.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgit2-debugsource-0.24.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libgit2-devel-0.24.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgit2-24-32bit-0.24.1-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libgit2-24-debuginfo-32bit-0.24.1-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgit2-24 / libgit2-24-32bit / libgit2-24-debuginfo / etc");
}

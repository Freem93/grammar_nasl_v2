#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-420.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84186);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/06/15 14:00:51 $");

  script_cve_id("CVE-2015-4041", "CVE-2015-4042");

  script_name(english:"openSUSE Security Update : coreutils / coreutils-testsuite (openSUSE-2015-420)");
  script_summary(english:"Check for the openSUSE-2015-420 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"coreutils was updated to fix one security issue and one non-security
bug.

The following vulnerability was fixed :

  - CVE-2015-4042: Use a later version of the patch that
    fixed (boo#928749, CVE-2015-4041), also avoiding I18N
    issue

The following bug was fixed :

  - boo#933396: adjust reference to info nodes in man pages"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=933396"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected coreutils / coreutils-testsuite packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coreutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coreutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coreutils-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:coreutils-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.2", reference:"coreutils-8.23-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"coreutils-debuginfo-8.23-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"coreutils-debugsource-8.23-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"coreutils-lang-8.23-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"coreutils-testsuite-8.23-2.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "coreutils-testsuite / coreutils / coreutils-debuginfo / etc");
}

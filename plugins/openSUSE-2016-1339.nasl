#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1339.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95272);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/11/23 14:38:51 $");

  script_cve_id("CVE-2014-3566", "CVE-2016-7067");

  script_name(english:"openSUSE Security Update : monit (openSUSE-2016-1339) (POODLE)");
  script_summary(english:"Check for the openSUSE-2016-1339 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for monit fixes the following issues :

  - CVE-2016-7067: A malicious attacker could have used a
    cross-site request forgery vulnerability to trick an
    authenticated user to perform monit actions.

Monit was updated to 5.20, containing all upstream improvements and
bug fixes.

The following tracked packaging bugs were fixed :

  - disable sslv3 according to RFC7568 (boo#974763)

  - fixed pid file directory (boo#971647)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974763"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected monit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monit-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/23");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"monit-5.20.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"monit-debuginfo-5.20.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"monit-debugsource-5.20.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"monit-5.20.0-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"monit-debuginfo-5.20.0-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"monit-debugsource-5.20.0-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"monit-5.20.0-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"monit-debuginfo-5.20.0-13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"monit-debugsource-5.20.0-13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "monit / monit-debuginfo / monit-debugsource");
}

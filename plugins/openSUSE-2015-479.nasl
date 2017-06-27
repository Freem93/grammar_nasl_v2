#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-479.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84658);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6491", "CVE-2014-6494", "CVE-2014-6496", "CVE-2014-6500", "CVE-2014-6507", "CVE-2014-6555", "CVE-2014-6559", "CVE-2014-6568", "CVE-2014-8964", "CVE-2015-0374", "CVE-2015-0381", "CVE-2015-0382", "CVE-2015-0411", "CVE-2015-0432", "CVE-2015-0433", "CVE-2015-0441", "CVE-2015-0499", "CVE-2015-0501", "CVE-2015-0505", "CVE-2015-2325", "CVE-2015-2326", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573", "CVE-2015-3152", "CVE-2015-4000");

  script_name(english:"openSUSE Security Update : MariaDB (openSUSE-2015-479) (BACKRONYM) (Logjam)");
  script_summary(english:"Check for the openSUSE-2015-479 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MariaDB was updated to its current minor version, fixing bugs and
security issues.

These updates include a fix for Logjam (CVE-2015-4000), making MariaDB
work with client software that no longer allows short DH groups over
SSL, as e.g. our current openssl packages.

On openSUSE 13.1, MariaDB was updated to 5.5.44.

On openSUSE 13.2, MariaDB was updated from 10.0.13 to 10.0.20.

Please read the release notes of MariaDB
https://mariadb.com/kb/en/mariadb/mariadb-10020-release-notes/
https://mariadb.com/kb/en/mariadb/mariadb-10019-release-notes/
https://mariadb.com/kb/en/mariadb/mariadb-10018-release-notes/
https://mariadb.com/kb/en/mariadb/mariadb-10017-release-notes/
https://mariadb.com/kb/en/mariadb/mariadb-10016-release-notes/
https://mariadb.com/kb/en/mariadb/mariadb-10015-release-notes/
https://mariadb.com/kb/en/mariadb/mariadb-10014-release-notes/ for
more information."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=859345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10014-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10015-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10016-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10017-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10018-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10019-release-notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://mariadb.com/kb/en/mariadb/mariadb-10020-release-notes/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MariaDB packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libmysqlclient-devel-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmysqlclient18-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmysqlclient18-debuginfo-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmysqlclient_r18-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmysqld-devel-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmysqld18-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmysqld18-debuginfo-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-bench-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-bench-debuginfo-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-client-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-client-debuginfo-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-debuginfo-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-debugsource-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-errormessages-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-test-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-test-debuginfo-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-tools-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mariadb-tools-debuginfo-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmysqlclient18-32bit-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-5.5.44-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient-devel-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient18-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient18-debuginfo-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient_r18-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqld-devel-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqld18-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqld18-debuginfo-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-bench-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-bench-debuginfo-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-client-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-client-debuginfo-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-debuginfo-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-debugsource-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-errormessages-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-test-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-test-debuginfo-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-tools-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-tools-debuginfo-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.20-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.20-2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-devel / libmysqlclient18-32bit / libmysqlclient18 / etc");
}

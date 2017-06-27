#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-607.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91277);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2015-3194", "CVE-2016-0639", "CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0655", "CVE-2016-0661", "CVE-2016-0665", "CVE-2016-0666", "CVE-2016-0668", "CVE-2016-0705", "CVE-2016-2047");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2016-607)");
  script_summary(english:"Check for the openSUSE-2016-607 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This mysql-community-server version update to 5.6.30 fixes the
following issues :

Security issues fixed :

  - fixed CVEs (boo#962779, boo#959724): CVE-2016-0705,
    CVE-2016-0639, CVE-2015-3194, CVE-2016-0640,
    CVE-2016-2047, CVE-2016-0644, CVE-2016-0646,
    CVE-2016-0647, CVE-2016-0648, CVE-2016-0649,
    CVE-2016-0650, CVE-2016-0665, CVE-2016-0666,
    CVE-2016-0641, CVE-2016-0642, CVE-2016-0655,
    CVE-2016-0661, CVE-2016-0668, CVE-2016-0643

  - changes
    http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-
    30.html
    http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-
    29.html

Bugs fixed :

  - don't delete the log data when migration fails

  - add 'log-error' and 'secure-file-priv' configuration
    options (added via configuration-tweaks.tar.bz2)
    [boo#963810]

  - add '/etc/my.cnf.d/error_log.conf' that specifies
    'log-error = /var/log/mysql/mysqld.log'. If no path is
    set, the error log is written to
    '/var/lib/mysql/$HOSTNAME.err', which is not picked up
    by logrotate.

  - add '/etc/my.cnf.d/secure_file_priv.conf' which
    specifies that 'LOAD DATA', 'SELECT ... INTO' and 'LOAD
    FILE()' will only work with files in the directory
    specified by 'secure-file-priv' option
    (='/var/lib/mysql-files')."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963810"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/20");
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

if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client18-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client18-debuginfo-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client_r18-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-bench-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-bench-debuginfo-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-client-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-client-debuginfo-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-debuginfo-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-debugsource-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-errormessages-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-test-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-test-debuginfo-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-tools-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-tools-debuginfo-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.30-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysql56client18-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysql56client18-debuginfo-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysql56client_r18-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-bench-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-bench-debuginfo-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-client-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-client-debuginfo-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-debuginfo-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-debugsource-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-errormessages-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-test-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-test-debuginfo-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-tools-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-tools-debuginfo-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.30-16.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.30-16.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysql56client18-32bit / libmysql56client18 / etc");
}

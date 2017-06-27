#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-555.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100039);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/24 13:36:52 $");

  script_cve_id("CVE-2016-5483", "CVE-2017-3302", "CVE-2017-3305", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3329", "CVE-2017-3450", "CVE-2017-3452", "CVE-2017-3453", "CVE-2017-3456", "CVE-2017-3461", "CVE-2017-3462", "CVE-2017-3463", "CVE-2017-3464", "CVE-2017-3599", "CVE-2017-3600");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2017-555) (Riddle)");
  script_summary(english:"Check for the openSUSE-2017-555 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mysql-community-server to version 5.6.36 fixes the
following issues :

These security issues were fixed :

  - CVE-2016-5483: Mysqldump failed to properly quote
    certain identifiers in SQL statements written to the
    dump output, allowing for execution of arbitrary
    commands (bsc#1029014)

  - CVE-2017-3305: MySQL client sent authentication request
    unencrypted even if SSL was required (aka Ridddle)
    (bsc#1029396).

  - CVE-2017-3308: Unspecified vulnerability in Server: DML
    (boo#1034850)

  - CVE-2017-3309: Unspecified vulnerability in Server:
    Optimizer (boo#1034850)

  - CVE-2017-3329: Unspecified vulnerability in Server:
    Thread (boo#1034850)

  - CVE-2017-3453: Unspecified vulnerability in Server:
    Optimizer (boo#1034850)

  - CVE-2017-3456: Unspecified vulnerability in Server: DML
    (boo#1034850)

  - CVE-2017-3461: Unspecified vulnerability in Server:
    Security (boo#1034850)

  - CVE-2017-3462: Unspecified vulnerability in Server:
    Security (boo#1034850)

  - CVE-2017-3463: Unspecified vulnerability in Server:
    Security (boo#1034850)

  - CVE-2017-3464: Unspecified vulnerability in Server: DDL
    (boo#1034850)

  - CVE-2017-3302: Crash in libmysqlclient.so (bsc#1022428).

  - CVE-2017-3450: Unspecified vulnerability Server:
    Memcached

  - CVE-2017-3452: Unspecified vulnerability Server:
    Optimizer

  - CVE-2017-3599: Unspecified vulnerability Server:
    Pluggable Auth

  - CVE-2017-3600: Unspecified vulnerability in Client:
    mysqldump (boo#1034850)

  - '--ssl-mode=REQUIRED' can be specified to require a
    secure connection (it fails if a secure connection
    cannot be obtained)

These non-security issues were fixed :

  - Set the default umask to 077 in mysql-systemd-helper
    (boo#1020976)

  - Change permissions of the configuration dir/files to
    755/644. Please note that storing the password in the
    /etc/my.cnf file is not safe. Use for example an option
    file that is accessible only by yourself (boo#889126)

For more information please see
http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=889126"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");
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

if ( rpm_check(release:"SUSE42.1", reference:"libmysql56client18-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysql56client18-debuginfo-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysql56client_r18-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-bench-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-bench-debuginfo-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-client-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-client-debuginfo-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-debuginfo-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-debugsource-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-errormessages-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-test-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-test-debuginfo-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-tools-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mysql-community-server-tools-debuginfo-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.36-25.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client18-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client18-debuginfo-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysql56client_r18-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-bench-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-bench-debuginfo-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-client-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-client-debuginfo-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-debuginfo-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-debugsource-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-errormessages-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-test-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-test-debuginfo-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-tools-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mysql-community-server-tools-debuginfo-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.36-24.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.36-24.3.3") ) flag++;

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

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-257.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97277);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/21 14:37:43 $");

  script_cve_id("CVE-2016-6664", "CVE-2017-3238", "CVE-2017-3243", "CVE-2017-3244", "CVE-2017-3257", "CVE-2017-3258", "CVE-2017-3265", "CVE-2017-3291", "CVE-2017-3312", "CVE-2017-3317", "CVE-2017-3318");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2017-257)");
  script_summary(english:"Check for the openSUSE-2017-257 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This mariadb version update to 10.0.29 fixes the following issues :

  - CVE-2017-3318: unspecified vulnerability affecting Error
    Handling (bsc#1020896)

  - CVE-2017-3317: unspecified vulnerability affecting
    Logging (bsc#1020894)

  - CVE-2017-3312: insecure error log file handling in
    mysqld_safe, incomplete CVE-2016-6664 (bsc#1020873)

  - CVE-2017-3291: unrestricted mysqld_safe's ledir
    (bsc#1020884)

  - CVE-2017-3265: unsafe chmod/chown use in init script
    (bsc#1020885)

  - CVE-2017-3258: unspecified vulnerability in the DDL
    component (bsc#1020875)

  - CVE-2017-3257: unspecified vulnerability affecting
    InnoDB (bsc#1020878)

  - CVE-2017-3244: unspecified vulnerability affecing the
    DML component (bsc#1020877)

  - CVE-2017-3243: unspecified vulnerability affecting the
    Charsets component (bsc#1020891)

  - CVE-2017-3238: unspecified vulnerability affecting the
    Optimizer component (bsc#1020882)

  - CVE-2016-6664: Root Privilege Escalation (bsc#1008253)

  - Applications using the client library for MySQL
    (libmysqlclient.so) had a use-after-free issue that
    could cause the applications to crash (bsc#1022428)

  - notable changes :

  - XtraDB updated to 5.6.34-79.1

  - TokuDB updated to 5.6.34-79.1

  - Innodb updated to 5.6.35

  - Performance Schema updated to 5.6.35

Release notes and changelog :

  - https://kb.askmonty.org/en/mariadb-10029-release-notes

  - https://kb.askmonty.org/en/mariadb-10029-changelog

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10029-changelog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10029-release-notes"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient-devel-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient18-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient18-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient_r18-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqld-devel-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqld18-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqld18-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-bench-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-bench-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-client-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-client-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-debugsource-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-errormessages-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-test-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-test-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-tools-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-tools-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient-devel-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient18-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient18-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient_r18-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld-devel-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld18-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld18-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-bench-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-bench-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-client-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-client-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-debugsource-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-errormessages-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-test-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-test-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-tools-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-tools-debuginfo-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.29-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.29-18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-devel / libmysqlclient18 / libmysqlclient18-32bit / etc");
}

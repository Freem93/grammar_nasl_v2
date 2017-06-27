#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1068.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93431);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2016-3477", "CVE-2016-3521", "CVE-2016-3615", "CVE-2016-5440");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2016-1068)");
  script_summary(english:"Check for the openSUSE-2016-1068 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mariadb fixes the following issues :

  - CVE-2016-3477: Unspecified vulnerability in subcomponent
    parser [bsc#991616]

  - CVE-2016-3521: Unspecified vulnerability in subcomponent
    types [bsc#991616] 

  - CVE-2016-3615: Unspecified vulnerability in subcomponent
    dml [bsc#991616] 

  - CVE-2016-5440: Unspecified vulnerability in subcomponent
    rbr [bsc#991616]

  - mariadb failing test main.bootstrap [bsc#984858]

  - left over 'openSUSE' comments in MariaDB on SLE12 GM and
    SP1 [bsc#985217]

  - remove unnecessary conditionals from specfile

  - add '--ignore-db-dir=lost+found' option to
    rc.mysql-multi in order not to misinterpret the
    lost+found directory as a database [bsc#986251]

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991616"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/12");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient-devel-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient18-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient18-debuginfo-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqlclient_r18-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqld-devel-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqld18-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libmysqld18-debuginfo-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-bench-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-bench-debuginfo-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-client-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-client-debuginfo-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-debuginfo-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-debugsource-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-errormessages-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-test-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-test-debuginfo-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-tools-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mariadb-tools-debuginfo-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.26-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.26-9.1") ) flag++;

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

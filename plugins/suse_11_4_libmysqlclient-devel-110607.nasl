#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libmysqlclient-devel-4676.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75904);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2010-3833", "CVE-2010-3834", "CVE-2010-3835", "CVE-2010-3836", "CVE-2010-3837", "CVE-2010-3838", "CVE-2010-3839", "CVE-2010-3840");
  script_osvdb_id(69001, 69387, 69390, 69391, 69392, 69393, 69394, 69395);

  script_name(english:"openSUSE Security Update : libmysqlclient-devel (openSUSE-SU-2011:1250-1)");
  script_summary(english:"Check for the libmysqlclient-devel-4676 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This mysql update fixes the following security issues

  - CVE-2010-3833: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Resource Management Errors
    (CWE-399)

  - CVE-2010-3834: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Insufficient Information
    (CWE-noinfo)

  - CVE-2010-3835: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Numeric Errors (CWE-189)

  - CVE-2010-3836: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Resource Management Errors
    (CWE-399)

  - CVE-2010-3837: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Resource Management Errors
    (CWE-399)

  - CVE-2010-3838: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Other (CWE-Other)

  - CVE-2010-3839: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Design Error
    (CWE-DesignError)

  - CVE-2010-3840: CVSS v2 Base Score: 4.0 (moderate)
    (AV:N/AC:L/Au:S/C:N/I:N/A:P): Other (CWE-Other)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-11/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=644864"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmysqlclient-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient16-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r16-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r16-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient-devel-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient16-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient16-debuginfo-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient_r16-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqlclient_r16-debuginfo-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqld-devel-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqld0-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmysqld0-debuginfo-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-bench-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-bench-debuginfo-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-client-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-client-debuginfo-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debug-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debug-debuginfo-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debuginfo-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-debugsource-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-test-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-test-debuginfo-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-tools-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mysql-community-server-tools-debuginfo-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient16-32bit-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient16-debuginfo-32bit-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient_r16-32bit-5.1.57-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", cpu:"x86_64", reference:"libmysqlclient_r16-debuginfo-32bit-5.1.57-0.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-410.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84134);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/11/16 15:47:33 $");

  script_cve_id("CVE-2013-4359", "CVE-2015-3306");

  script_name(english:"openSUSE Security Update : proftpd (openSUSE-2015-410)");
  script_summary(english:"Check for the openSUSE-2015-410 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The ftp server ProFTPD was updated to 1.3.5a to fix one security
issue.

The following vulnerability was fixed :

  - CVE-2015-3306: Unauthenticated copying of files via SITE
    CPFR/CPTO allowed by mod_copy (boo#927290)

In addition, proftpd was updated to 1.3.5a to fix a number of upstream
bugs and improve functionality."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927290"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected proftpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD 1.3.5 Mod_Copy Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-radius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:proftpd-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"proftpd-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-debuginfo-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-debugsource-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-devel-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-lang-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-ldap-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-ldap-debuginfo-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-mysql-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-mysql-debuginfo-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-pgsql-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-pgsql-debuginfo-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-radius-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-radius-debuginfo-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-sqlite-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"proftpd-sqlite-debuginfo-1.3.5a-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-debuginfo-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-debugsource-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-devel-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-lang-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-ldap-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-ldap-debuginfo-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-mysql-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-mysql-debuginfo-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-pgsql-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-pgsql-debuginfo-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-radius-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-radius-debuginfo-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-sqlite-1.3.5a-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"proftpd-sqlite-debuginfo-1.3.5a-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "proftpd / proftpd-debuginfo / proftpd-debugsource / proftpd-devel / etc");
}

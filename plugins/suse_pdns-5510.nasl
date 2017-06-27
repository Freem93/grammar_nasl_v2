#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update pdns-5510.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33887);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/13 20:36:48 $");

  script_cve_id("CVE-2008-3337");

  script_name(english:"openSUSE 10 Security Update : pdns (pdns-5510)");
  script_summary(english:"Check for the pdns-5510 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of pdns offers better spoofing resistance by not ignoring
invalid queries. (CVE-2008-3337)"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pdns packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-sqlite2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-backend-sqlite3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"pdns-2.9.20-16") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"pdns-backend-ldap-2.9.20-16") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"pdns-backend-mysql-2.9.20-16") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"pdns-backend-postgresql-2.9.20-16") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"pdns-backend-sqlite2-2.9.20-16") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"pdns-2.9.21-57.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"pdns-backend-ldap-2.9.21-57.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"pdns-backend-mysql-2.9.21-57.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"pdns-backend-postgresql-2.9.21-57.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"pdns-backend-sqlite2-2.9.21-57.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"pdns-backend-sqlite3-2.9.21-57.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdns-recursor");
}

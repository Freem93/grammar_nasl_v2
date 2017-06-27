#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update courier-authlib-5352.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33223);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:06:06 $");

  script_cve_id("CVE-2008-2667");

  script_name(english:"openSUSE 10 Security Update : courier-authlib (courier-authlib-5352)");
  script_summary(english:"Check for the courier-authlib-5352 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of courier-authlib fixes a bug that allowed SQL
injections. (CVE-2008-2667)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected courier-authlib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:courier-authlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:courier-authlib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:courier-authlib-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:courier-authlib-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:courier-authlib-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:courier-authlib-pipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:courier-authlib-userdb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/19");
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

if ( rpm_check(release:"SUSE10.2", reference:"courier-authlib-0.58-38") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"courier-authlib-devel-0.58-38") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"courier-authlib-ldap-0.58-38") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"courier-authlib-mysql-0.58-38") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"courier-authlib-pgsql-0.58-38") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"courier-authlib-pipe-0.58-38") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"courier-authlib-userdb-0.58-38") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"courier-authlib-0.59.3-44.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"courier-authlib-devel-0.59.3-44.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"courier-authlib-ldap-0.59.3-44.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"courier-authlib-mysql-0.59.3-44.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"courier-authlib-pgsql-0.59.3-44.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"courier-authlib-pipe-0.59.3-44.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"courier-authlib-userdb-0.59.3-44.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "courier-authlib");
}

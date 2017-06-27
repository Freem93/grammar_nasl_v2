#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-289.
#

include("compat.inc");

if (description)
{
  script_id(24083);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:46:26 $");

  script_xref(name:"FEDORA", value:"2006-289");

  script_name(english:"Fedora Core 5 : php-5.1.4-1 (2006-289)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest release of PHP 5, version 5.1.4. This
release includes fixes for several security issues and many bug fixes.

The phpinfo() PHP function did not properly sanitize long strings. An
attacker could use this to perform cross-site scripting attacks
against sites that have publicly-available PHP scripts that call
phpinfo(). (CVE-2006-0996)

The html_entity_decode() PHP function was found to not be binary safe.
An attacker could use this flaw to disclose a certain part of the
memory. In order for this issue to be exploitable the target site
would need to have a PHP script which called the
'html_entity_decode()' function with untrusted input from the user and
displayed the result. (CVE-2006-1490)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-May/000073.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99b87013"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"php-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-bcmath-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-dba-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-debuginfo-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-devel-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-gd-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-imap-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-ldap-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-mbstring-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-mysql-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-ncurses-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-odbc-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-pdo-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-pgsql-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-snmp-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-soap-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-xml-5.1.4-1")) flag++;
if (rpm_check(release:"FC5", reference:"php-xmlrpc-5.1.4-1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-dba / php-debuginfo / php-devel / php-gd / etc");
}

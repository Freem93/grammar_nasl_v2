#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-455.
#

include("compat.inc");

if (description)
{
  script_id(25101);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 22:04:02 $");

  script_xref(name:"FEDORA", value:"2007-455");

  script_name(english:"Fedora Core 5 : php-5.1.6-1.5 (2007-455)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a number of security issues in PHP.

A denial of service flaw was found in the way PHP processed a deeply
nested array. A remote attacker could cause the PHP interpreter to
crash by submitting an input variable with a deeply nested array.
(CVE-2007-1285)

A flaw was found in the way the mbstring extension set global
variables. A script which used the mb_parse_str() function to set
global variables could be forced to enable the register_globals
configuration option, possibly resulting in global variable injection.
(CVE-2007-1583)

A flaw was discovered in the way PHP's mail() function processed
header data. If a script sent mail using a Subject header containing a
string from an untrusted source, a remote attacker could send bulk
e-mail to unintended recipients. (CVE-2007-1718)

A heap based buffer overflow flaw was discovered in PHP's gd
extension. A script that could be forced to process WBMP images from
an untrusted source could result in arbitrary code execution.
(CVE-2007-1001)

A buffer over-read flaw was discovered in PHP's gd extension. A script
that could be forced to write arbitrary strings using a JIS font from
an untrusted source could cause the PHP interpreter to crash.
(CVE-2007-0455)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-April/001680.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2ea3315"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/30");
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
if (rpm_check(release:"FC5", reference:"php-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-bcmath-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-dba-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-debuginfo-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-devel-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-gd-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-imap-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-ldap-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-mbstring-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-mysql-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-ncurses-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-odbc-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-pdo-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-pgsql-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-snmp-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-soap-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-xml-5.1.6-1.5")) flag++;
if (rpm_check(release:"FC5", reference:"php-xmlrpc-5.1.6-1.5")) flag++;


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

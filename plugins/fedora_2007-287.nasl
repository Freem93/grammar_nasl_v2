#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-287.
#

include("compat.inc");

if (description)
{
  script_id(24717);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 21:54:55 $");

  script_xref(name:"FEDORA", value:"2007-287");

  script_name(english:"Fedora Core 5 : php-5.1.6-1.4 (2007-287)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a number of security issues in PHP.

A number of buffer overflow flaws were found in the PHP session
extension, the str_replace() function, and the imap_mail_compose()
function. If very long strings under the control of an attacker are
passed to the str_replace() function then an integer overflow could
occur in memory allocation. If a script uses the imap_mail_compose()
function to create a new MIME message based on an input body from an
untrusted source, it could result in a heap overflow. An attacker who
is able to access a PHP application affected by any these issues could
trigger these flaws and possibly execute arbitrary code as the
'apache' user. (CVE-2007-0906)

If unserializing untrusted data on 64-bit platforms, the
zend_hash_init() function can be forced to enter an infinite loop,
consuming CPU resources for a limited length of time, until the script
timeout alarm aborts execution of the script. (CVE-2007-0988)

If the wddx extension is used to import WDDX data from an untrusted
source, certain WDDX input packets may allow a random portion of heap
memory to be exposed. (CVE-2007-0908)

If the odbc_result_all() function is used to display data from a
database, and the contents of the database table are under the control
of an attacker, a format string vulnerability is possible which could
lead to the execution of arbitrary code. (CVE-2007-0909)

A one byte memory read will always occur before the beginning of a
buffer, which could be triggered for example by any use of the
header() function in a script. However it is unlikely that this would
have any effect. (CVE-2007-0907)

Several flaws in PHP could allows attackers to 'clobber' certain
super-global variables via unspecified vectors. (CVE-2007-0910)

The Fedora Project would like to thank Stefan Esser for his help
diagnosing these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001509.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40c1ecd3"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/27");
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
if (rpm_check(release:"FC5", reference:"php-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-bcmath-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-dba-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-debuginfo-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-devel-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-gd-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-imap-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-ldap-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-mbstring-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-mysql-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-ncurses-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-odbc-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-pdo-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-pgsql-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-snmp-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-soap-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-xml-5.1.6-1.4")) flag++;
if (rpm_check(release:"FC5", reference:"php-xmlrpc-5.1.6-1.4")) flag++;


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

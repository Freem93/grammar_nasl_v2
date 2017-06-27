#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-1024.
#

include("compat.inc");

if (description)
{
  script_id(24032);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/05 16:01:14 $");

  script_bugtraq_id(19415, 19582, 20349);
  script_xref(name:"FEDORA", value:"2006-1024");

  script_name(english:"Fedora Core 5 : php-5.1.6-1.1 (2006-1024)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest upstream release of PHP 5.1, version
5.1.6, fixing a number of security vulnerabilities, and other bugs.

An integer overflow was discovered in the PHP memory handling
routines. If a script can cause memory allocation based on untrusted
user data, a remote attacker sending a carefully crafted request could
execute arbitrary code as the 'apache' user. (CVE-2006-4812)

A buffer overflow was discovered in the PHP sscanf() function. If a
script used the sscanf() function with positional arguments in the
format string, a remote attacker sending a carefully crafted request
could execute arbitrary code as the 'apache' user. (CVE-2006-4020)

An integer overflow was discovered in the PHP wordwrap() and
str_repeat() functions. If a script running on a 64-bit server used
either of these functions on untrusted user data, a remote attacker
sending a carefully crafted request might be able to cause a heap
overflow. (CVE-2006-4482)

A buffer overflow was discovered in the PHP gd extension. If a script
was set up to process GIF images from untrusted sources using the gd
extension, a remote attacker could cause a heap overflow.
(CVE-2006-4484)

A buffer overread was discovered in the PHP stripos() function. If a
script used the stripos() function with untrusted user data, PHP may
read past the end of a buffer, which could allow a denial of service
attack by a remote user. (CVE-2006-4485)

An integer overflow was discovered in the PHP memory allocation
handling. On 64-bit platforms, the 'memory_limit' setting was not
enforced correctly, which could allow a denial of service attack by a
remote user. (CVE-2006-4486)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-October/000666.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc45eb90"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC5", reference:"php-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-bcmath-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-dba-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-debuginfo-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-devel-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-gd-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-imap-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-ldap-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-mbstring-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-mysql-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-ncurses-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-odbc-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-pdo-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-pgsql-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-snmp-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-soap-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-xml-5.1.6-1.1")) flag++;
if (rpm_check(release:"FC5", reference:"php-xmlrpc-5.1.6-1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-dba / php-debuginfo / php-devel / php-gd / etc");
}

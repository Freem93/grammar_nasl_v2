#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-518.
#

include("compat.inc");

if (description)
{
  script_id(18625);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 21:38:05 $");

  script_cve_id("CVE-2005-1921");
  script_xref(name:"FEDORA", value:"2005-518");

  script_name(english:"Fedora Core 4 : php-5.0.4-10.3 (2005-518)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the PEAR XML_RPC 1.3.1 package, which fixes a
security issue in the XML_RPC server implementation. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-1921 to this issue.

The bundled version of shtool is also updated, to fix some temporary
file handling races. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1751 to this issue.

Bug fixes for the dom, ldap, and gd extensions are also included in
this update.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-July/001032.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5402118"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP XML-RPC Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"php-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-bcmath-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-dba-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-debuginfo-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-devel-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-gd-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-imap-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-ldap-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-mbstring-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-mysql-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-ncurses-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-odbc-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-pear-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-pgsql-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-snmp-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-soap-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-xml-5.0.4-10.3")) flag++;
if (rpm_check(release:"FC4", reference:"php-xmlrpc-5.0.4-10.3")) flag++;


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

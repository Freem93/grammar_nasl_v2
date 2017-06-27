#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisories ELSA-2006-0730 / 
# ELSA-2006-0669.
#

include("compat.inc");

if (description)
{
  script_id(67421);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/07/14 23:36:28 $");

  script_cve_id("CVE-2006-3016", "CVE-2006-4020", "CVE-2006-4482", "CVE-2006-4484", "CVE-2006-4486", "CVE-2006-5465");
  script_osvdb_id(25253, 27824, 28001, 28002, 28003, 28004, 30178, 30179);
  script_xref(name:"RHSA", value:"2006:0669");
  script_xref(name:"RHSA", value:"2006:0730");

  script_name(english:"Oracle Linux 4 : php (ELSA-2006-0730 / ELSA-2006-0669)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix a security issue are now available. 

This update has been rated as having important security impact by the
Red Hat Security Response Team. 

PHP is an HTML-embedded scripting language commonly used with the Apache
HTTP Web server. 

Users of PHP should upgrade to these updated packages which contain
backported patches to correct these issues.  These packages also contain
a fix for a bug where certain input strings to the metaphone() function
could cause memory corruption. 


From Red Hat Security Advisory 2006:0730 :

The Hardened-PHP Project discovered an overflow in the PHP
htmlentities() and htmlspecialchars() routines. If a PHP script used
the vulnerable functions to parse UTF-8 data, a remote attacker
sending a carefully crafted request could trigger the overflow and
potentially execute arbitrary code as the 'apache' user.
(CVE-2006-5465)


From Red Hat Security Advisory 2006:0669 :

A response-splitting issue was discovered in the PHP session handling.
If a remote attacker can force a carefully crafted session identifier
to be used, a cross-site-scripting or response-splitting attack could
be possible. (CVE-2006-3016)

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

An integer overflow was discovered in the PHP memory allocation
handling. On 64-bit platforms, the 'memory_limit' setting was not
enforced correctly, which could allow a denial of service attack by a
remote user. (CVE-2006-4486)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-November/000016.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);


flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-devel-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-devel-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-domxml-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-domxml-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-gd-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-gd-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-imap-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-imap-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-ldap-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-ldap-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-mbstring-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-mbstring-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-mysql-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-mysql-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-ncurses-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-ncurses-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-odbc-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-odbc-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-pear-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-pear-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-pgsql-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-pgsql-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-snmp-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-snmp-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"php-xmlrpc-4.3.9-3.22")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"php-xmlrpc-4.3.9-3.22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");


#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0669. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22443);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/29 15:35:20 $");

  script_cve_id("CVE-2006-3016", "CVE-2006-4020", "CVE-2006-4482", "CVE-2006-4484", "CVE-2006-4486");
  script_osvdb_id(25253, 27824, 28001, 28002, 28003, 28004);
  script_xref(name:"RHSA", value:"2006:0669");

  script_name(english:"RHEL 3 / 4 : php (RHSA-2006:0669)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

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
remote user. (CVE-2006-4486)

Users of PHP should upgrade to these updated packages which contain
backported patches to correct these issues. These packages also
contain a fix for a bug where certain input strings to the metaphone()
function could cause memory corruption."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-3016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-4020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-4482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-4484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-4486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0669.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0669";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL3", reference:"php-4.3.2-36.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-devel-4.3.2-36.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-imap-4.3.2-36.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-ldap-4.3.2-36.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-mysql-4.3.2-36.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-odbc-4.3.2-36.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-pgsql-4.3.2-36.ent")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-devel-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-domxml-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-gd-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-imap-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-ldap-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-mbstring-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-mysql-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-ncurses-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-odbc-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-pear-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-pgsql-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-snmp-4.3.9-3.18")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-xmlrpc-4.3.9-3.18")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-devel / php-domxml / php-gd / php-imap / php-ldap / etc");
  }
}

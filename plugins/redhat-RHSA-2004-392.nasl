#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:392. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(13653);
  script_version ("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/28 17:44:44 $");

  script_cve_id("CVE-2004-0594", "CVE-2004-0595");
  script_xref(name:"RHSA", value:"2004:392");

  script_name(english:"RHEL 3 : php (RHSA-2004:392)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix various security issues are now
available.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP server.

Stefan Esser discovered a flaw when memory_limit is enabled in
versions of PHP 4 before 4.3.8. If a remote attacker could force the
PHP interpreter to allocate more memory than the memory_limit setting
before script execution begins, then the attacker may be able to
supply the contents of a PHP hash table remotely. This hash table
could then be used to execute arbitrary code as the 'apache' user. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0594 to this issue.

This issue has a higher risk when PHP is running on an instance of
Apache which is vulnerable to CVE-2004-0493. For Red Hat Enterprise
Linux 3, this Apache memory exhaustion issue was fixed by a previous
update, RHSA-2004:342. It may also be possible to exploit this issue
if using a non-default PHP configuration with the 'register_defaults'
setting is changed to 'On'. Red Hat does not believe that this flaw is
exploitable in the default configuration of Red Hat Enterprise Linux
3.

Stefan Esser discovered a flaw in the strip_tags function in versions
of PHP before 4.3.8. The strip_tags function is commonly used by PHP
scripts to prevent Cross-Site-Scripting attacks by removing HTML tags
from user-supplied form data. By embedding NUL bytes into form data,
HTML tags can in some cases be passed intact through the strip_tags
function, which may allow a Cross-Site-Scripting attack. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2004-0595 to this issue.

All users of PHP are advised to upgrade to these updated packages,
which contain backported patches that address these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0594.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0595.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-392.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:392";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL3", reference:"php-4.3.2-11.1.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-imap-4.3.2-11.1.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-ldap-4.3.2-11.1.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-mysql-4.3.2-11.1.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-odbc-4.3.2-11.1.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-pgsql-4.3.2-11.1.ent")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-imap / php-ldap / php-mysql / php-odbc / php-pgsql");
  }
}

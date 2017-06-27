#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:831. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20206);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/28 18:06:54 $");

  script_cve_id("CVE-2005-3353", "CVE-2005-3388", "CVE-2005-3389", "CVE-2005-3390");
  script_bugtraq_id(15248, 15249, 15250);
  script_osvdb_id(18906);
  script_xref(name:"RHSA", value:"2005:831");

  script_name(english:"RHEL 3 / 4 : php (RHSA-2005:831)");
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

A flaw was found in the way PHP registers global variables during a
file upload request. A remote attacker could submit a carefully
crafted multipart/form-data POST request that would overwrite the
$GLOBALS array, altering expected script behavior, and possibly
leading to the execution of arbitrary PHP commands. Please note that
this vulnerability only affects installations which have
register_globals enabled in the PHP configuration file, which is not a
default or recommended option. The Common Vulnerabilities and
Exposures project assigned the name CVE-2005-3390 to this issue.

A flaw was found in the PHP parse_str() function. If a PHP script
passes only one argument to the parse_str() function, and the script
can be forced to abort execution during operation (for example due to
the memory_limit setting), the register_globals may be enabled even if
it is disabled in the PHP configuration file. This vulnerability only
affects installations that have PHP scripts using the parse_str
function in this way. (CVE-2005-3389)

A Cross-Site Scripting flaw was found in the phpinfo() function. If a
victim can be tricked into following a malicious URL to a site with a
page displaying the phpinfo() output, it may be possible to inject
JavaScript or HTML content into the displayed page or steal data such
as cookies. This vulnerability only affects installations which allow
users to view the output of the phpinfo() function. As the phpinfo()
function outputs a large amount of information about the current state
of PHP, it should only be used during debugging or if protected by
authentication. (CVE-2005-3388)

A denial of service flaw was found in the way PHP processes EXIF image
data. It is possible for an attacker to cause PHP to crash by
supplying carefully crafted EXIF image data. (CVE-2005-3353)

Users of PHP should upgrade to these updated packages, which contain
backported patches that resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3388.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3389.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-3390.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-831.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2005:831";
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
  if (rpm_check(release:"RHEL3", reference:"php-4.3.2-26.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-devel-4.3.2-26.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-imap-4.3.2-26.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-ldap-4.3.2-26.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-mysql-4.3.2-26.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-odbc-4.3.2-26.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"php-pgsql-4.3.2-26.ent")) flag++;

  if (rpm_check(release:"RHEL4", reference:"php-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-devel-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-domxml-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-gd-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-imap-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-ldap-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-mbstring-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-mysql-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-ncurses-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-odbc-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-pear-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-pgsql-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-snmp-4.3.9-3.9")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-xmlrpc-4.3.9-3.9")) flag++;

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

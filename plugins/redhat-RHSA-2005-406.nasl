#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:406. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18198);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/28 17:55:18 $");

  script_cve_id("CVE-2004-1392", "CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043");
  script_xref(name:"RHSA", value:"2005:406");

  script_name(english:"RHEL 4 : PHP (RHSA-2005:406)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix various security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A bug was found in the way PHP processes IFF and JPEG images. It is
possible to cause PHP to consume CPU resources for a short period of
time by supplying a carefully crafted IFF or JPEG image. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
names CVE-2005-0524 and CVE-2005-0525 to these issues.

A buffer overflow bug was also found in the way PHP processes EXIF
image headers. It is possible for an attacker to construct an image
file in such a way it could execute arbitrary instructions when
processed by PHP. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1042 to this issue.

A denial of service bug was found in the way PHP processes EXIF image
headers. It is possible for an attacker to cause PHP to enter an
infinite loop for a short period of time by supplying a carefully
crafted image file to PHP for processing. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2005-1043 to this issue.

Several bug fixes are also included in this update :

  - some performance issues in the unserialize() function
    have been fixed

  - the behaviour of the interpreter when handling integer
    overflow during conversion of a floating variable to an
    integer has been reverted to match the behaviour used
    upstream; the integer will now be wrapped rather than
    truncated

  - a fix for the virtual() function in the Apache httpd
    module which would flush the response prematurely

  - the hard-coded default 'safe mode' setting is now
    'disabled' rather than 'enabled'; to match the default
    /etc/php.ini setting

  - in the curl extension, safe mode was not enforced for
    'file:///' URL lookups (CVE-2004-1392).

Users of PHP should upgrade to these updated packages, which contain
backported fixes for these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-1392.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0524.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1043.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-406.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/04");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:406";
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
  if (rpm_check(release:"RHEL4", reference:"php-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-devel-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-domxml-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-gd-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-imap-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-ldap-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-mbstring-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-mysql-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-ncurses-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-odbc-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-pear-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-pgsql-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-snmp-4.3.9-3.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"php-xmlrpc-4.3.9-3.6")) flag++;

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

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0021. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80440);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2014-3669", "CVE-2014-3670");
  script_bugtraq_id(70611, 70665);
  script_osvdb_id(113421, 113423);
  script_xref(name:"RHSA", value:"2015:0021");

  script_name(english:"RHEL 6 : php (RHSA-2015:0021)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix two security issues are now available
for Red Hat Enterprise Linux 6.5 Extended Update Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A buffer overflow flaw was found in the Exif extension. A specially
crafted JPEG or TIFF file could cause a PHP application using the
exif_thumbnail() function to crash or, possibly, execute arbitrary
code with the privileges of the user running that PHP application.
(CVE-2014-3670)

An integer overflow flaw was found in the way custom objects were
unserialized. Specially crafted input processed by the unserialize()
function could cause a PHP application to crash. (CVE-2014-3669)

All php users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3669.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3670.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0021.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-zts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6\.5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.5", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0021";
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
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-bcmath-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-bcmath-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-bcmath-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-cli-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-cli-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-cli-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-common-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-common-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-common-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-dba-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-dba-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-dba-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-debuginfo-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-debuginfo-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-debuginfo-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-devel-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-devel-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-devel-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-embedded-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-embedded-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-embedded-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-enchant-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-enchant-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-enchant-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-fpm-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-fpm-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-fpm-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-gd-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-gd-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-gd-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-imap-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-imap-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-imap-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-intl-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-intl-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-intl-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-ldap-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-ldap-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-ldap-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-mbstring-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-mbstring-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-mbstring-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-mysql-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-mysql-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-mysql-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-odbc-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-odbc-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-odbc-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-pdo-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-pdo-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-pdo-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-pgsql-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-pgsql-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-pgsql-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-process-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-process-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-process-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-pspell-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-pspell-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-pspell-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-recode-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-recode-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-recode-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-snmp-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-snmp-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-snmp-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-soap-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-soap-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-soap-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-tidy-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-tidy-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-tidy-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-xml-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-xml-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-xml-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-xmlrpc-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-xmlrpc-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-xmlrpc-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"i686", reference:"php-zts-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"s390x", reference:"php-zts-5.3.3-27.el6_5.3")) flag++;
  if (rpm_check(release:"RHEL6", sp:"5", cpu:"x86_64", reference:"php-zts-5.3.3-27.el6_5.3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
  }
}

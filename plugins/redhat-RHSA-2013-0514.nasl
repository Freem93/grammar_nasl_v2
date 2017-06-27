#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0514. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64762);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2011-1398", "CVE-2012-0831", "CVE-2012-2688");
  script_xref(name:"RHSA", value:"2013:0514");

  script_name(english:"RHEL 6 : php (RHSA-2013:0514)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix three security issues, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

It was found that PHP did not check for carriage returns in HTTP
headers, allowing intended HTTP response splitting protections to be
bypassed. Depending on the web browser the victim is using, a remote
attacker could use this flaw to perform HTTP response splitting
attacks. (CVE-2011-1398)

An integer signedness issue, leading to a heap-based buffer underflow,
was found in the PHP scandir() function. If a remote attacker could
upload an excessively large number of files to a directory the
scandir() function runs on, it could cause the PHP interpreter to
crash or, possibly, execute arbitrary code. (CVE-2012-2688)

It was found that PHP did not correctly handle the magic_quotes_gpc
configuration directive. This could result in magic_quotes_gpc input
escaping not being applied in all cases, possibly making it easier for
a remote attacker to perform SQL injection attacks. (CVE-2012-0831)

These updated php packages also include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.4
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All users of php are advised to upgrade to these updated packages,
which fix these issues and add these enhancements. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1398.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2688.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faae67f0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0514.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?879a0985"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0514";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-bcmath-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-bcmath-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-bcmath-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-cli-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-cli-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-cli-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-common-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-common-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-common-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-dba-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-dba-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-dba-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-debuginfo-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-debuginfo-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-debuginfo-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-devel-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-devel-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-devel-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-embedded-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-embedded-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-embedded-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-enchant-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-enchant-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-enchant-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-fpm-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-fpm-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-fpm-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-gd-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-gd-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-gd-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-imap-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-imap-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-imap-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-intl-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-intl-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-intl-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-ldap-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-ldap-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-ldap-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mbstring-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mbstring-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mbstring-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mysql-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mysql-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mysql-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-odbc-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-odbc-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-odbc-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pdo-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pdo-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pdo-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pgsql-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pgsql-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pgsql-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-process-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-process-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-process-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pspell-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pspell-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pspell-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-recode-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-recode-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-recode-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-snmp-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-snmp-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-snmp-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-soap-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-soap-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-soap-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-tidy-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-tidy-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-tidy-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xml-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xml-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xml-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xmlrpc-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xmlrpc-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xmlrpc-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-zts-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-zts-5.3.3-22.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-zts-5.3.3-22.el6")) flag++;

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

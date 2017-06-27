#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1046. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59752);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2010-2950", "CVE-2011-4153", "CVE-2012-0057", "CVE-2012-0781", "CVE-2012-0789", "CVE-2012-1172", "CVE-2012-2143", "CVE-2012-2336", "CVE-2012-2386");
  script_bugtraq_id(40173, 47545, 51992, 53729);
  script_osvdb_id(66086, 72399, 78570, 78571, 78676, 79332, 81633, 81791, 82509, 82510, 82577, 82578);
  script_xref(name:"RHSA", value:"2012:1046");
  script_xref(name:"TRA", value:"TRA-2012-01");

  script_name(english:"RHEL 6 : php (RHSA-2012:1046)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

It was discovered that the PHP XSL extension did not restrict the file
writing capability of libxslt. A remote attacker could use this flaw
to create or overwrite an arbitrary file that is writable by the user
running PHP, if a PHP script processed untrusted eXtensible Style
Sheet Language Transformations (XSLT) content. (CVE-2012-0057)

Note: This update disables file writing by default. A new PHP
configuration directive, 'xsl.security_prefs', can be used to enable
file writing in XSLT.

A flaw was found in the way PHP validated file names in file upload
requests. A remote attacker could possibly use this flaw to bypass the
sanitization of the uploaded file names, and cause a PHP script to
store the uploaded file in an unexpected directory, by using a
directory traversal attack. (CVE-2012-1172)

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the way the PHP phar extension processed
certain fields of tar archive files. A remote attacker could provide a
specially crafted tar archive file that, when processed by a PHP
application using the phar extension, could cause the application to
crash or, potentially, execute arbitrary code with the privileges of
the user running PHP. (CVE-2012-2386)

A format string flaw was found in the way the PHP phar extension
processed certain PHAR files. A remote attacker could provide a
specially crafted PHAR file, which once processed in a PHP application
using the phar extension, could lead to information disclosure and
possibly arbitrary code execution via a crafted phar:// URI.
(CVE-2010-2950)

A flaw was found in the DES algorithm implementation in the crypt()
password hashing function in PHP. If the password string to be hashed
contained certain characters, the remainder of the string was ignored
when calculating the hash, significantly reducing the password
strength. (CVE-2012-2143)

Note: With this update, passwords are no longer truncated when
performing DES hashing. Therefore, new hashes of the affected
passwords will not match stored hashes generated using vulnerable PHP
versions, and will need to be updated.

It was discovered that the fix for CVE-2012-1823, released via
RHSA-2012:0546, did not properly filter all php-cgi command line
arguments. A specially crafted request to a PHP script could cause the
PHP interpreter to execute the script in a loop, or output usage
information that triggers an Internal Server Error. (CVE-2012-2336)

A memory leak flaw was found in the PHP strtotime() function call. A
remote attacker could possibly use this flaw to cause excessive memory
consumption by triggering many strtotime() function calls.
(CVE-2012-0789)

A NULL pointer dereference flaw was found in the PHP tidy_diagnose()
function. A remote attacker could use specially crafted input to crash
an application that uses tidy::diagnose. (CVE-2012-0781)

It was found that PHP did not check the zend_strndup() function's
return value in certain cases. A remote attacker could possibly use
this flaw to crash a PHP application. (CVE-2011-4153)

Upstream acknowledges Rubin Xu and Joseph Bonneau as the original
reporters of CVE-2012-2143.

All php users should upgrade to these updated packages, which contain
backported patches to resolve these issues. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2950.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4153.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0057.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0781.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0789.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1172.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2336.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2386.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2012-0546.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2012-01"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:1046";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-bcmath-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-bcmath-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-bcmath-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-cli-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-cli-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-cli-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-common-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-common-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-common-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-dba-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-dba-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-dba-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-debuginfo-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-debuginfo-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-debuginfo-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-devel-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-devel-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-devel-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-embedded-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-embedded-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-embedded-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-enchant-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-enchant-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-enchant-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-gd-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-gd-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-gd-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-imap-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-imap-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-imap-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-intl-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-intl-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-intl-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-ldap-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-ldap-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-ldap-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mbstring-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mbstring-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mbstring-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mysql-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mysql-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mysql-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-odbc-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-odbc-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-odbc-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pdo-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pdo-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pdo-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pgsql-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pgsql-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pgsql-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-process-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-process-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-process-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pspell-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pspell-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pspell-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-recode-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-recode-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-recode-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-snmp-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-snmp-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-snmp-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-soap-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-soap-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-soap-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-tidy-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-tidy-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-tidy-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xml-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xml-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xml-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xmlrpc-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xmlrpc-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xmlrpc-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-zts-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-zts-5.3.3-14.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-zts-5.3.3-14.el6_3")) flag++;


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

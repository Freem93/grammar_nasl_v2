#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0919 and 
# Oracle Linux Security Advisory ELSA-2010-0919 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68150);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 16:53:48 $");

  script_cve_id("CVE-2009-5016", "CVE-2010-0397", "CVE-2010-1128", "CVE-2010-1917", "CVE-2010-2531", "CVE-2010-3065", "CVE-2010-3870");
  script_bugtraq_id(38430, 38708, 41991, 44605, 44889);
  script_xref(name:"RHSA", value:"2010:0919");

  script_name(english:"Oracle Linux 4 / 5 : php (ELSA-2010-0919)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0919 :

Updated php packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

An input validation flaw was discovered in the PHP session serializer.
If a PHP script generated session variable names from untrusted user
input, a remote attacker could use this flaw to inject an arbitrary
variable into the PHP session. (CVE-2010-3065)

An information leak flaw was discovered in the PHP var_export()
function implementation. If some fatal error occurred during the
execution of this function (such as the exhaustion of memory or script
execution time limit), part of the function's output was sent to the
user as script output, possibly leading to the disclosure of sensitive
information. (CVE-2010-2531)

A numeric truncation error and an input validation flaw were found in
the way the PHP utf8_decode() function decoded partial multi-byte
sequences for some multi-byte encodings, sending them to output
without them being escaped. An attacker could use these flaws to
perform a cross-site scripting attack. (CVE-2009-5016, CVE-2010-3870)

It was discovered that the PHP lcg_value() function used insufficient
entropy to seed the pseudo-random number generator. A remote attacker
could possibly use this flaw to predict values returned by the
function, which are used to generate session identifiers by default.
This update changes the function's implementation to use more entropy
during seeding. (CVE-2010-1128)

It was discovered that the PHP fnmatch() function did not restrict the
length of the pattern argument. A remote attacker could use this flaw
to crash the PHP interpreter where a script used fnmatch() on
untrusted matching patterns. (CVE-2010-1917)

A NULL pointer dereference flaw was discovered in the PHP XML-RPC
extension. A malicious XML-RPC client or server could use this flaw to
crash the PHP interpreter via a specially crafted XML-RPC request.
(CVE-2010-0397)

All php users should upgrade to these updated packages, which contain
backported patches to resolve these issues. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-November/001749.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-November/001750.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"php-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-devel-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-domxml-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-gd-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-imap-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-ldap-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-mbstring-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-mysql-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-ncurses-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-odbc-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-pear-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-pgsql-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-snmp-4.3.9-3.31")) flag++;
if (rpm_check(release:"EL4", reference:"php-xmlrpc-4.3.9-3.31")) flag++;

if (rpm_check(release:"EL5", reference:"php-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-bcmath-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-cli-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-common-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-dba-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-devel-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-gd-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-imap-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-ldap-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-mbstring-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-mysql-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-ncurses-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-odbc-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-pdo-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-pgsql-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-snmp-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-soap-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-xml-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"EL5", reference:"php-xmlrpc-5.1.6-27.el5_5.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-devel / etc");
}

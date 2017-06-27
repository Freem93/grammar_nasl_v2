#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0196 and 
# Oracle Linux Security Advisory ELSA-2011-0196 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68192);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/01 16:57:58 $");

  script_cve_id("CVE-2010-3710", "CVE-2010-4156", "CVE-2010-4645");
  script_bugtraq_id(43926, 44727, 45668);
  script_xref(name:"RHSA", value:"2011:0196");

  script_name(english:"Oracle Linux 5 : php53 (ELSA-2011-0196)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0196 :

Updated php53 packages that fix three security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A flaw was found in the way PHP converted certain floating point
values from string representation to a number. If a PHP script
evaluated an attacker's input in a numeric context, the PHP
interpreter could cause high CPU usage until the script execution time
limit is reached. This issue only affected i386 systems.
(CVE-2010-4645)

A stack memory exhaustion flaw was found in the way the PHP
filter_var() function validated email addresses. An attacker could use
this flaw to crash the PHP interpreter by providing excessively long
input to be validated as an email address. (CVE-2010-3710)

A memory disclosure flaw was found in the PHP multi-byte string
extension. If the mb_strcut() function was called with a length
argument exceeding the input string size, the function could disclose
a portion of the PHP interpreter's memory. (CVE-2010-4156)

All php53 users should upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001813.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php53 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"php53-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-bcmath-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-cli-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-common-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-dba-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-devel-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-gd-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-imap-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-intl-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-ldap-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-mbstring-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-mysql-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-odbc-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-pdo-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-pgsql-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-process-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-pspell-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-snmp-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-soap-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-xml-5.3.3-1.el5_6.1")) flag++;
if (rpm_check(release:"EL5", reference:"php53-xmlrpc-5.3.3-1.el5_6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php53 / php53-bcmath / php53-cli / php53-common / php53-dba / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1609 and 
# Oracle Linux Security Advisory ELSA-2016-1609 respectively.
#

include("compat.inc");

if (description)
{
  script_id(92936);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2016-5385");
  script_osvdb_id(141667);
  script_xref(name:"RHSA", value:"2016:1609");

  script_name(english:"Oracle Linux 6 : php (ELSA-2016-1609) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:1609 :

An update for php is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

Security Fix(es) :

* It was discovered that PHP did not properly protect against the
HTTP_PROXY variable name clash. A remote attacker could possibly use
this flaw to redirect HTTP requests performed by a PHP script to an
attacker-controlled proxy via a malicious HTTP request.
(CVE-2016-5385)

Red Hat would like to thank Scott Geary (VendHQ) for reporting this
issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-August/006270.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:php-zts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"php-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-bcmath-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-cli-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-common-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-dba-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-devel-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-embedded-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-enchant-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-fpm-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-gd-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-imap-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-intl-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-ldap-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-mbstring-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-mysql-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-odbc-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-pdo-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-pgsql-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-process-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-pspell-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-recode-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-snmp-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-soap-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-tidy-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-xml-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-xmlrpc-5.3.3-48.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"php-zts-5.3.3-48.el6_8")) flag++;


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

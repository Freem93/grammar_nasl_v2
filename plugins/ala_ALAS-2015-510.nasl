#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-510.
#

include("compat.inc");

if (description)
{
  script_id(82857);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/05 13:44:21 $");

  script_cve_id("CVE-2015-1351", "CVE-2015-1352", "CVE-2015-3329");
  script_xref(name:"ALAS", value:"2015-510");

  script_name(english:"Amazon Linux AMI : php55 (ALAS-2015-510)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A use-after-free flaw was found in PHP's OPcache extension. This flaw
could possibly lead to a disclosure of portion of server memory.
(CVE-2015-1351)

A NULL pointer dereference flaw was found in PHP's pgsql extension. A
specially crafted table name passed to function as pg_insert() or
pg_select() could cause a PHP application to crash. (CVE-2015-1352)

A buffer overflow flaw was found in the way PHP's Phar extension
parsed Phar archives. A specially crafted archive could cause PHP to
crash or, possibly, execute arbitrary code when opened.
(CVE-2015-3329)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-510.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php55' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"php55-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-bcmath-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-cli-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-common-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-dba-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-debuginfo-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-devel-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-embedded-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-enchant-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-fpm-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-gd-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-gmp-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-imap-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-intl-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-ldap-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mbstring-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mcrypt-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mssql-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mysqlnd-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-odbc-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-opcache-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pdo-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pgsql-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-process-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pspell-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-recode-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-snmp-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-soap-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-tidy-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-xml-5.5.24-1.100.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-xmlrpc-5.5.24-1.100.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php55 / php55-bcmath / php55-cli / php55-common / php55-dba / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-211.
#

include("compat.inc");

if (description)
{
  script_id(69769);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:54 $");

  script_cve_id("CVE-2013-4113");
  script_xref(name:"ALAS", value:"2013-211");
  script_xref(name:"RHSA", value:"2013:1049");

  script_name(english:"Amazon Linux AMI : php (ALAS-2013-211)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow flaw was found in the way PHP parsed deeply nested
XML documents. If a PHP application used the xml_parse_into_struct()
function to parse untrusted XML content, an attacker able to supply
specially crafted XML could use this flaw to crash the application or,
possibly, execute arbitrary code with the privileges of the user
running the PHP interpreter. (CVE-2013-4113)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-211.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"php-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-bcmath-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-cli-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-common-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-dba-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-debuginfo-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-devel-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-embedded-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-enchant-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-fpm-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-gd-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-imap-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-intl-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ldap-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mbstring-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mcrypt-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mssql-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mysql-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mysqlnd-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-odbc-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pdo-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pgsql-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-process-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pspell-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-recode-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-snmp-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-soap-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-tidy-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-xml-5.3.27-1.0.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-xmlrpc-5.3.27-1.0.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
}

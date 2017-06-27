#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-362.
#

include("compat.inc");

if (description)
{
  script_id(78305);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-0237", "CVE-2014-0238");
  script_xref(name:"ALAS", value:"2014-362");

  script_name(english:"Amazon Linux AMI : php55 (ALAS-2014-362)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The cdf_unpack_summary_info function in cdf.c in the Fileinfo
component in PHP before 5.4.29 and 5.5.x before 5.5.13 allows remote
attackers to cause a denial of service (performance degradation) by
triggering many file_printf calls.

The cdf_read_property_info function in cdf.c in the Fileinfo component
in PHP before 5.4.29 and 5.5.x before 5.5.13 allows remote attackers
to cause a denial of service (infinite loop or out-of-bounds memory
access) via a vector that (1) has zero length or (2) is too long."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-362.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php55' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"php55-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-bcmath-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-cli-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-common-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-dba-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-debuginfo-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-devel-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-embedded-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-enchant-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-fpm-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-gd-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-gmp-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-imap-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-intl-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-ldap-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mbstring-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mcrypt-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mssql-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-mysqlnd-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-odbc-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-opcache-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pdo-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pgsql-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-process-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pspell-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-recode-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-snmp-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-soap-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-tidy-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-xml-5.5.13-3.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-xmlrpc-5.5.13-3.74.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php55 / php55-bcmath / php55-cli / php55-common / php55-dba / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-706.
#

include("compat.inc");

if (description)
{
  script_id(91465);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2013-7456", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096");
  script_xref(name:"ALAS", value:"2016-706");

  script_name(english:"Amazon Linux AMI : php56 (ALAS-2016-706)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security-related issues were resolved :

Out-of-bounds read in imagescale (CVE-2013-7456)

Integer underflow causing arbitrary null write in fread/gzread
(CVE-2016-5096)

Integer overflow in php_html_entities() (CVE-2016-5094)

Integer overflow in php_filter_full_special_chars() (CVE-2016-5095)

Out-of-bounds heap read in get_icu_value_internal (CVE-2016-5093)

(Updated 2016-06-15: CVE-2016-5095 was fixed in this version, but was
not previously listed in this errata.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-706.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php56' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"php56-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-bcmath-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-cli-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-common-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-dba-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-dbg-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-debuginfo-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-devel-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-embedded-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-enchant-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-fpm-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-gd-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-gmp-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-imap-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-intl-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-ldap-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mbstring-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mcrypt-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mssql-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-mysqlnd-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-odbc-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-opcache-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pdo-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pgsql-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-process-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pspell-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-recode-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-snmp-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-soap-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-tidy-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-xml-5.6.22-1.125.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-xmlrpc-5.6.22-1.125.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php56 / php56-bcmath / php56-cli / php56-common / php56-dba / etc");
}

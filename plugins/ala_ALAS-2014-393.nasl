#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-393.
#

include("compat.inc");

if (description)
{
  script_id(78336);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2013-6712", "CVE-2014-0207", "CVE-2014-0237", "CVE-2014-0238", "CVE-2014-3515", "CVE-2014-3981", "CVE-2014-4049");
  script_xref(name:"ALAS", value:"2014-393");

  script_name(english:"Amazon Linux AMI : php (ALAS-2014-393)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A denial of service flaw was found in the way the File Information
(fileinfo) extension parsed certain Composite Document Format (CDF)
files. A remote attacker could use this flaw to crash a PHP
application using fileinfo via a specially crafted CDF file.

acinclude.m4, as used in the configure script in PHP 5.5.13 and
earlier, allows local users to overwrite arbitrary files via a symlink
attack on the /tmp/phpglibccheck file.

A buffer over-read flaw was found in the way the DateInterval class
parsed interval specifications. An attacker able to make a PHP
application parse a specially crafted specification using DateInterval
could possibly cause the PHP interpreter to crash.

A heap-based buffer overflow flaw was found in the way PHP parsed DNS
TXT records. A malicious DNS server or a man-in-the-middle attacker
could possibly use this flaw to execute arbitrary code as the PHP
interpreter if a PHP application used the dns_get_record() function to
perform a DNS query.

A type confusion issue was found in the SPL ArrayObject and
SPLObjectStorage classes' unserialize() method. A remote attacker able
to submit specially crafted input to a PHP application, which would
then unserialize this input using one of the aforementioned methods,
could use this flaw to execute arbitrary code with the privileges of
the user running that PHP application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-393.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update php' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/21");
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
if (rpm_check(release:"ALA", reference:"php-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-bcmath-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-cli-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-common-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-dba-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-debuginfo-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-devel-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-embedded-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-enchant-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-fpm-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-gd-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-imap-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-intl-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ldap-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mbstring-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mcrypt-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mssql-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mysql-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mysqlnd-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-odbc-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pdo-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pgsql-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-process-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pspell-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-recode-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-snmp-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-soap-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-tidy-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-xml-5.3.29-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-xmlrpc-5.3.29-1.7.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-7.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78268);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/27 16:45:01 $");

  script_cve_id("CVE-2011-1148", "CVE-2011-1938", "CVE-2011-2202", "CVE-2011-2483", "CVE-2011-3182", "CVE-2011-3379");
  script_xref(name:"ALAS", value:"2011-7");

  script_name(english:"Amazon Linux AMI : php (ALAS-2011-7)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PHP before 5.3.7 does not properly check the return values of the
malloc, calloc, and realloc library functions, which allows
context-dependent attackers to cause a denial of service (NULL pointer
dereference and application crash) or trigger a buffer overflow by
leveraging the ability to provide an arbitrary value for a function
argument, related to (1) ext/curl/interface.c, (2)
ext/date/lib/parse_date.c, (3) ext/date/lib/parse_iso_intervals.c, (4)
ext/date/lib/parse_tz.c, (5) ext/date/lib/timelib.c, (6)
ext/pdo_odbc/pdo_odbc.c, (7) ext/reflection/php_reflection.c, (8)
ext/soap/php_sdl.c, (9) ext/xmlrpc/libxmlrpc/base64.c, (10)
TSRM/tsrm_win32.c, and (11) the strtotime function.

The is_a function in PHP 5.3.7 and 5.3.8 triggers a call to the
__autoload function, which makes it easier for remote attackers to
execute arbitrary code by providing a crafted URL and leveraging
potentially unsafe behavior in certain PEAR packages and custom
autoloaders.

php: changes to is_a() in 5.3.7 may allow arbitrary code execution
with certain code

A signedness issue was found in the way the PHP crypt() function
handled 8-bit characters in passwords when using Blowfish hashing. Up
to three characters immediately preceding a non-ASCII character (one
with the high bit set) had no effect on the hash result, thus
shortening the effective password length. This made brute-force
guessing more efficient as several different passwords were hashed to
the same value.

A signedness issue was found in the way the crypt() function in the
PostgreSQL pgcrypto module handled 8-bit characters in passwords when
using Blowfish hashing. Up to three characters immediately preceding a
non-ASCII character (one with the high bit set) had no effect on the
hash result, thus shortening the effective password length. This made
brute-force guessing more efficient as several different passwords
were hashed to the same value.

crypt_blowfish before 1.1, as used in PHP before 5.3.7 on certain
platforms, PostgreSQL before 8.4.9, and other products, does not
properly handle 8-bit characters, which makes it easier for
context-dependent attackers to determine a cleartext password by
leveraging knowledge of a password hash.

A stack-based buffer overflow flaw was found in the way the PHP socket
extension handled long AF_UNIX socket addresses. An attacker able to
make a PHP script connect to a long AF_UNIX socket address could use
this flaw to crash the PHP interpreter.

Stack-based buffer overflow in the socket_connect function in
ext/sockets/sockets.c in PHP 5.3.3 through 5.3.6 might allow
context-dependent attackers to execute arbitrary code via a long
pathname for a UNIX socket.

The rfc1867_post_handler function in main/rfc1867.c in PHP before
5.3.7 does not properly restrict filenames in multipart/form-data POST
requests, which allows remote attackers to conduct absolute path
traversal attacks, and possibly create or overwrite arbitrary files,
via a crafted upload request, related to a 'file path injection
vulnerability.'

An off-by-one flaw was found in PHP. If an attacker uploaded a file
with a specially crafted file name it could cause a PHP script to
attempt to write a file to the root (/) directory. By default, PHP
runs as the 'apache' user, preventing it from writing to the root
directory.

The rfc1867_post_handler function in main/rfc1867.c in PHP before
5.3.7 does not properly restrict filenames in multipart/form-data POST
requests, which allows remote attackers to conduct absolute path
traversal attacks, and possibly create or overwrite arbitrary files,
via a crafted upload request, related to a 'file path injection
vulnerability.'

Use-after-free vulnerability in the substr_replace function in PHP
5.3.6 and earlier allows context-dependent attackers to cause a denial
of service (memory corruption) or possibly have unspecified other
impact by using the same variable for multiple arguments.

A use-after-free flaw was found in the PHP substr_replace() function.
If a PHP script used the same variable as multiple function arguments,
a remote attacker could possibly use this to crash the PHP interpreter
or, possibly, execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-7.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mssql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php-zts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"php-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-bcmath-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-cli-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-common-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-dba-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-debuginfo-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-devel-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-embedded-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-fpm-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-gd-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-imap-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-intl-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-ldap-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mbstring-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mcrypt-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mssql-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-mysql-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-odbc-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pdo-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pgsql-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-process-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-pspell-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-snmp-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-soap-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-tidy-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-xml-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-xmlrpc-5.3.8-3.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php-zts-5.3.8-3.19.amzn1")) flag++;

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

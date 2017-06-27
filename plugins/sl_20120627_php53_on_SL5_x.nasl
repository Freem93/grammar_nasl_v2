#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61356);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/23 13:44:41 $");

  script_cve_id("CVE-2010-2950", "CVE-2011-4153", "CVE-2012-0057", "CVE-2012-0789", "CVE-2012-1172", "CVE-2012-2143", "CVE-2012-2336", "CVE-2012-2386");
  script_xref(name:"TRA", value:"TRA-2012-01");

  script_name(english:"Scientific Linux Security Update : php53 on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PHP is an HTML-embedded scripting language commonly used with the
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

It was discovered that the fix for CVE-2012-1823, released via a
previous update, did not properly filter all php-cgi command line
arguments. A specially crafted request to a PHP script could cause the
PHP interpreter to execute the script in a loop, or output usage
information that triggers an Internal Server Error. (CVE-2012-2336)

A memory leak flaw was found in the PHP strtotime() function call. A
remote attacker could possibly use this flaw to cause excessive memory
consumption by triggering many strtotime() function calls.
(CVE-2012-0789)

It was found that PHP did not check the zend_strndup() function's
return value in certain cases. A remote attacker could possibly use
this flaw to crash a PHP application. (CVE-2011-4153)

All php53 users should upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=594
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd96e1a5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2012-01"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"php53-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-bcmath-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-cli-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-common-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-dba-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-debuginfo-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-devel-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-gd-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-imap-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-intl-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-ldap-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-mbstring-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-mysql-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-odbc-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pdo-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pgsql-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-process-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pspell-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-snmp-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-soap-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-xml-5.3.3-13.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php53-xmlrpc-5.3.3-13.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

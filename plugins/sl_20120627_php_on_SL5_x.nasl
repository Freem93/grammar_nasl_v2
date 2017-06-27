#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61357);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/23 13:44:41 $");

  script_cve_id("CVE-2011-4153", "CVE-2012-0057", "CVE-2012-0789", "CVE-2012-1172", "CVE-2012-2336");
  script_xref(name:"TRA", value:"TRA-2012-01");

  script_name(english:"Scientific Linux Security Update : php on SL5.x i386/x86_64");
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

It was discovered that the fix for CVE-2012-1823, released via a
previous update, did not properly filter all php-cgi command line
arguments. A specially crafted request to a PHP script could cause the
PHP interpreter to output usage information that triggers an Internal
Server Error. (CVE-2012-2336)

A memory leak flaw was found in the PHP strtotime() function call. A
remote attacker could possibly use this flaw to cause excessive memory
consumption by triggering many strtotime() function calls.
(CVE-2012-0789)

It was found that PHP did not check the zend_strndup() function's
return value in certain cases. A remote attacker could possibly use
this flaw to crash a PHP application. (CVE-2011-4153)

All php users should upgrade to these updated packages, which contain
backported patches to resolve these issues. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=469
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84546206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2012-01"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
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
if (rpm_check(release:"SL5", reference:"php-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-bcmath-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-cli-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-common-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-dba-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-debuginfo-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-devel-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-gd-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-imap-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-ldap-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-mbstring-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-mysql-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-ncurses-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-odbc-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-pdo-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-pgsql-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-snmp-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-soap-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-xml-5.1.6-39.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-xmlrpc-5.1.6-39.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

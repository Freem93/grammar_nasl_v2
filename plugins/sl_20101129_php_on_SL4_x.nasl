#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60908);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2009-5016", "CVE-2010-0397", "CVE-2010-1128", "CVE-2010-1917", "CVE-2010-2531", "CVE-2010-3065", "CVE-2010-3870");

  script_name(english:"Scientific Linux Security Update : php on SL4.x, SL5.x i386/x86_64");
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
"An input validation flaw was discovered in the PHP session serializer.
If a PHP script generated session variable names from untrusted user
input, a remote attacker could use this flaw to inject an arbitrary
variable into the PHP session. (CVE-2010-3065)

An information leak flaw was discovered in the PHP var_export()
function implementation. If some fatal error occurred during the
execution of this function (such as the exhaustion of memory or script
execution time limit), part of the function's output was sent to the
user as script output, possibly leading to the disclosure of sensitive
information. (CVE-2010-2531)

A numeric truncation error and an input validation flaw were found in
the way the PHP utf8_decode() function decoded partial multi-byte
sequences for some multi-byte encodings, sending them to output
without them being escaped. An attacker could use these flaws to
perform a cross-site scripting attack. (CVE-2009-5016, CVE-2010-3870)

It was discovered that the PHP lcg_value() function used insufficient
entropy to seed the pseudo-random number generator. A remote attacker
could possibly use this flaw to predict values returned by the
function, which are used to generate session identifiers by default.
This update changes the function's implementation to use more entropy
during seeding. (CVE-2010-1128)

It was discovered that the PHP fnmatch() function did not restrict the
length of the pattern argument. A remote attacker could use this flaw
to crash the PHP interpreter where a script used fnmatch() on
untrusted matching patterns. (CVE-2010-1917)

A NULL pointer dereference flaw was discovered in the PHP XML-RPC
extension. A malicious XML-RPC client or server could use this flaw to
crash the PHP interpreter via a specially crafted XML-RPC request.
(CVE-2010-0397)

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1011&L=scientific-linux-errata&T=0&P=1564
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9eb0b151"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"php-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-devel-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-domxml-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-gd-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-imap-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-ldap-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-mbstring-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-mysql-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-ncurses-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-odbc-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-pear-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-pgsql-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-snmp-4.3.9-3.31")) flag++;
if (rpm_check(release:"SL4", reference:"php-xmlrpc-4.3.9-3.31")) flag++;

if (rpm_check(release:"SL5", reference:"php-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-bcmath-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-cli-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-common-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-dba-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-devel-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-gd-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-imap-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-ldap-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-mbstring-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-mysql-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-ncurses-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-odbc-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-pdo-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-pgsql-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-snmp-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-soap-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-xml-5.1.6-27.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"php-xmlrpc-5.1.6-27.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

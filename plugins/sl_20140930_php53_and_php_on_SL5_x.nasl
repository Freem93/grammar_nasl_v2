#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(78419);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/14 10:52:33 $");

  script_cve_id("CVE-2012-1571", "CVE-2014-2497", "CVE-2014-3587", "CVE-2014-3597", "CVE-2014-4670", "CVE-2014-4698");

  script_name(english:"Scientific Linux Security Update : php53 and php on SL5.x, SL6.x i386/x86_64");
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
"It was found that the fix for CVE-2012-1571 was incomplete; the File
Information (fileinfo) extension did not correctly parse certain
Composite Document Format (CDF) files. A remote attacker could use
this flaw to crash a PHP application using fileinfo via a specially
crafted CDF file. (CVE-2014-3587)

A NULL pointer dereference flaw was found in the
gdImageCreateFromXpm() function of PHP's gd extension. A remote
attacker could use this flaw to crash a PHP application using gd via a
specially crafted X PixMap (XPM) file. (CVE-2014-2497)

Multiple buffer over-read flaws were found in the php_parserr()
function of PHP. A malicious DNS server or a man-in-the-middle
attacker could possibly use this flaw to execute arbitrary code as the
PHP interpreter if a PHP application used the dns_get_record()
function to perform a DNS query. (CVE-2014-3597)

Two use-after-free flaws were found in the way PHP handled certain
Standard PHP Library (SPL) Iterators and ArrayIterators. A malicious
script author could possibly use either of these flaws to disclose
certain portions of server memory. (CVE-2014-4670, CVE-2014-4698)

The CVE-2014-3597 issue was discovered by David Kutlek of the Red Hat
BaseOS QE.

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1410&L=scientific-linux-errata&T=0&P=675
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72f1614c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"php53-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-bcmath-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-cli-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-common-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-dba-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-debuginfo-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-devel-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-gd-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-imap-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-intl-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-ldap-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-mbstring-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-mysql-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-odbc-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pdo-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pgsql-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-process-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-pspell-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-snmp-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-soap-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-xml-5.3.3-24.el5")) flag++;
if (rpm_check(release:"SL5", reference:"php53-xmlrpc-5.3.3-24.el5")) flag++;

if (rpm_check(release:"SL6", reference:"php-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-bcmath-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-cli-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-common-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-dba-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-debuginfo-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-devel-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-embedded-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-enchant-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-fpm-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-gd-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-imap-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-intl-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-ldap-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-mbstring-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-mysql-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-odbc-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-pdo-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-pgsql-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-process-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-pspell-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-recode-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-snmp-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-soap-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-tidy-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-xml-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-xmlrpc-5.3.3-27.el6_5.2")) flag++;
if (rpm_check(release:"SL6", reference:"php-zts-5.3.3-27.el6_5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

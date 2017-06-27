#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60445);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-4782", "CVE-2007-5898", "CVE-2007-5899", "CVE-2008-2051", "CVE-2008-2107", "CVE-2008-2108");

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
"It was discovered that the PHP escapeshellcmd() function did not
properly escape multi-byte characters which are not valid in the
locale used by the script. This could allow an attacker to bypass
quoting restrictions imposed by escapeshellcmd() and execute arbitrary
commands if the PHP script was using certain locales. Scripts using
the default UTF-8 locale are not affected by this issue.
(CVE-2008-2051)

PHP functions htmlentities() and htmlspecialchars() did not properly
recognize partial multi-byte sequences. Certain sequences of bytes
could be passed through these functions without being correctly
HTML-escaped. Depending on the browser being used, an attacker could
use this flaw to conduct cross-site scripting attacks. (CVE-2007-5898)

A PHP script which used the transparent session ID configuration
option, or which used the output_add_rewrite_var() function, could
leak session identifiers to external websites. If a page included an
HTML form with an ACTION attribute referencing a non-local URL, the
user's session ID would be included in the form data passed to that
URL. (CVE-2007-5899)

It was discovered that PHP fnmatch() function did not restrict the
length of the string argument. An attacker could use this flaw to
crash the PHP interpreter where a script used fnmatch() on untrusted
input data. (CVE-2007-4782)

It was discovered that PHP did not properly seed its pseudo-random
number generator used by functions such as rand() and mt_rand(),
possibly allowing an attacker to easily predict the generated
pseudo-random values. (CVE-2008-2107, CVE-2008-2108)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=1671
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a8e3180"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 189, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"php-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-bcmath-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-cli-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-common-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-dba-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-devel-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-gd-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-imap-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-ldap-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-mbstring-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-mysql-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-ncurses-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-odbc-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-pdo-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-pgsql-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-snmp-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-soap-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-xml-5.1.6-20.el5_2.1")) flag++;
if (rpm_check(release:"SL5", reference:"php-xmlrpc-5.1.6-20.el5_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

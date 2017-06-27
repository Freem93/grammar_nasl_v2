#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61312);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-1823");

  script_name(english:"Scientific Linux Security Update : php on SL5.x, SL6.x i386/x86_64");
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

A flaw was found in the way the php-cgi executable processed command
line arguments when running in CGI mode. A remote attacker could send
a specially crafted request to a PHP script that would result in the
query string being parsed by php-cgi as command line options and
arguments. This could lead to the disclosure of the script's source
code or arbitrary code execution with the privileges of the PHP
interpreter. (CVE-2012-1823)

Scientific Linux is aware that a public exploit for this issue is
available that allows remote code execution in affected PHP CGI
configurations. This flaw does not affect the default configuration in
Scientific Linux 5 and 6 using the PHP module for Apache httpd to
handle PHP scripts.

All php users should upgrade to these updated packages, which contain
a backported patch to resolve this issue. After installing the updated
packages, the httpd daemon must be restarted for the update to take
effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1205&L=scientific-linux-errata&T=0&P=337
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee80ca9d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/07");
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
if (rpm_check(release:"SL5", reference:"php-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-bcmath-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-cli-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-common-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-dba-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-debuginfo-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-devel-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-gd-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-imap-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-ldap-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-mbstring-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-mysql-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-ncurses-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-odbc-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-pdo-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-pgsql-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-snmp-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-soap-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-xml-5.1.6-34.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"php-xmlrpc-5.1.6-34.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"php-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-bcmath-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-cli-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-common-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-dba-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-debuginfo-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-devel-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-embedded-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-enchant-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-gd-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-imap-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-intl-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-ldap-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-mbstring-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-mysql-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-odbc-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-pdo-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-pgsql-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-process-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-pspell-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-recode-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-snmp-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-soap-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-tidy-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-xml-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-xmlrpc-5.3.3-3.el6_2.8")) flag++;
if (rpm_check(release:"SL6", reference:"php-zts-5.3.3-3.el6_2.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

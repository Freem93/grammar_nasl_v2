#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(68868);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/08/25 02:35:59 $");

  script_cve_id("CVE-2013-4113");

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
"A buffer overflow flaw was found in the way PHP parsed deeply nested
XML documents. If a PHP application used the xml_parse_into_struct()
function to parse untrusted XML content, an attacker able to supply
specially- crafted XML could use this flaw to crash the application
or, possibly, execute arbitrary code with the privileges of the user
running the PHP interpreter. (CVE-2013-4113)

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1307&L=scientific-linux-errata&T=0&P=952
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07dbb32d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"php-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-bcmath-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-cli-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-common-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-dba-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-debuginfo-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-devel-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-gd-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-imap-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-ldap-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-mbstring-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-mysql-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-ncurses-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-odbc-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-pdo-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-pgsql-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-snmp-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-soap-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-xml-5.1.6-40.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"php-xmlrpc-5.1.6-40.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"php-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-bcmath-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-cli-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-common-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-dba-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-debuginfo-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-devel-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-embedded-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-enchant-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-fpm-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-gd-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-imap-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-intl-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-ldap-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-mbstring-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-mysql-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-odbc-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-pdo-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-pgsql-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-process-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-pspell-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-recode-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-snmp-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-soap-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-tidy-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-xml-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-xmlrpc-5.3.3-23.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"php-zts-5.3.3-23.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

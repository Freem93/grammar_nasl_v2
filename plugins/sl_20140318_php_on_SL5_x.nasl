#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(73115);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/03/20 10:47:40 $");

  script_cve_id("CVE-2006-7243", "CVE-2009-0689");

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
"A buffer overflow flaw was found in the way PHP parsed floating point
numbers from their text representation. If a PHP application converted
untrusted input strings to numbers, an attacker able to provide such
input could cause the application to crash or, possibly, execute
arbitrary code with the privileges of the application. (CVE-2009-0689)

It was found that PHP did not properly handle file names with a NULL
character. A remote attacker could possibly use this flaw to make a
PHP script access unexpected files and bypass intended file system
access restrictions. (CVE-2006-7243)

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1403&L=scientific-linux-errata&T=0&P=1702
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a2e6332"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");
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
if (rpm_check(release:"SL5", reference:"php-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-bcmath-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-cli-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-common-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-dba-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-debuginfo-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-devel-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-gd-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-imap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-ldap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-mbstring-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-mysql-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-ncurses-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-odbc-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-pdo-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-pgsql-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-snmp-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-soap-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-xml-5.1.6-44.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"php-xmlrpc-5.1.6-44.el5_10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

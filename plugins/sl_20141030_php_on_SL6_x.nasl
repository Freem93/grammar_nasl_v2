#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(78853);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/15 16:37:17 $");

  script_cve_id("CVE-2014-3668", "CVE-2014-3669", "CVE-2014-3670", "CVE-2014-3710");

  script_name(english:"Scientific Linux Security Update : php on SL6.x, SL7.x i386/x86_64");
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
"A buffer overflow flaw was found in the Exif extension. A specially
crafted JPEG or TIFF file could cause a PHP application using the
exif_thumbnail() function to crash or, possibly, execute arbitrary
code with the privileges of the user running that PHP application.
(CVE-2014-3670)

An integer overflow flaw was found in the way custom objects were
unserialized. Specially crafted input processed by the unserialize()
function could cause a PHP application to crash. (CVE-2014-3669)

An out-of-bounds read flaw was found in the way the File Information
(fileinfo) extension parsed Executable and Linkable Format (ELF)
files. A remote attacker could use this flaw to crash a PHP
application using fileinfo via a specially crafted ELF file.
(CVE-2014-3710)

An out of bounds read flaw was found in the way the xmlrpc extension
parsed dates in the ISO 8601 format. A specially crafted XML-RPC
request or response could possibly cause a PHP application to crash.
(CVE-2014-3668)

The CVE-2014-3710 issue was discovered by Francisco Alonso of Red Hat
Product Security.

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8471af0f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"php-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-bcmath-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-cli-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-common-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-dba-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-debuginfo-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-devel-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-embedded-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-enchant-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-fpm-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-gd-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-imap-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-intl-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-ldap-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-mbstring-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-mysql-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-odbc-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pdo-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pgsql-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-process-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pspell-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-recode-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-snmp-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-soap-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-tidy-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-xml-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-xmlrpc-5.3.3-40.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-zts-5.3.3-40.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-bcmath-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-cli-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-common-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-dba-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-debuginfo-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-devel-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-embedded-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-enchant-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-fpm-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-gd-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-intl-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-ldap-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mbstring-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mysql-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-mysqlnd-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-odbc-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pdo-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pgsql-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-process-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-pspell-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-recode-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-snmp-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-soap-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-xml-5.4.16-23.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"php-xmlrpc-5.4.16-23.el7_0.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

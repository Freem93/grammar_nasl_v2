#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61220);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/13 15:30:40 $");

  script_cve_id("CVE-2011-0708", "CVE-2011-1148", "CVE-2011-1466", "CVE-2011-1469", "CVE-2011-2202", "CVE-2011-4566", "CVE-2011-4885");

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

It was found that the hashing routine used by PHP arrays was
susceptible to predictable hash collisions. If an HTTP POST request to
a PHP application contained many parameters whose names map to the
same hash value, a large amount of CPU time would be consumed. This
flaw has been mitigated by adding a new configuration directive,
max_input_vars, that limits the maximum number of parameters processed
per request. By default, max_input_vars is set to 1000.
(CVE-2011-4885)

A use-after-free flaw was found in the PHP substr_replace() function.
If a PHP script used the same variable as multiple function arguments,
a remote attacker could possibly use this to crash the PHP interpreter
or, possibly, execute arbitrary code. (CVE-2011-1148)

An integer overflow flaw was found in the PHP exif extension. On
32-bit systems, a specially crafted image file could cause the PHP
interpreter to crash or disclose portions of its memory when a PHP
script tries to extract Exchangeable image file format (Exif) metadata
from the image file. (CVE-2011-4566)

An insufficient input validation flaw, leading to a buffer over-read,
was found in the PHP exif extension. A specially crafted image file
could cause the PHP interpreter to crash when a PHP script tries to
extract Exchangeable image file format (Exif) metadata from the image
file. (CVE-2011-0708)

An integer overflow flaw was found in the PHP calendar extension. A
remote attacker able to make a PHP script call SdnToJulian() with a
large value could cause the PHP interpreter to crash. (CVE-2011-1466)

A bug in the PHP Streams component caused the PHP interpreter to crash
if an FTP wrapper connection was made through an HTTP proxy. A remote
attacker could possibly trigger this issue if a PHP script accepted an
untrusted URL to connect to. (CVE-2011-1469)

An off-by-one flaw was found in PHP. If an attacker uploaded a file
with a specially crafted file name it could cause a PHP script to
attempt to write a file to the root (/) directory. By default, PHP
runs as the 'apache' user, preventing it from writing to the root
directory. (CVE-2011-2202)

All php users should upgrade to these updated packages, which contain
backported patches to resolve these issues. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1201&L=scientific-linux-errata&T=0&P=1113
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c72914b5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/18");
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
if (rpm_check(release:"SL5", reference:"php-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-bcmath-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-cli-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-common-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-dba-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-debuginfo-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-devel-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-gd-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-imap-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-ldap-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-mbstring-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-mysql-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-ncurses-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-odbc-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-pdo-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-pgsql-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-snmp-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-soap-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-xml-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"SL5", reference:"php-xmlrpc-5.1.6-27.el5_7.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

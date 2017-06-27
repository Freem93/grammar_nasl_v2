#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(84661);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/19 14:25:12 $");

  script_cve_id("CVE-2014-9425", "CVE-2014-9705", "CVE-2014-9709", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-2301", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3307", "CVE-2015-3329", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4026", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603");

  script_name(english:"Scientific Linux Security Update : php on SL6.x i386/x86_64");
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
"A flaw was found in the way PHP parsed multipart HTTP POST requests. A
specially crafted request could cause PHP to use an excessive amount
of CPU time. (CVE-2015-4024)

An uninitialized pointer use flaw was found in PHP's Exif extension. A
specially crafted JPEG or TIFF file could cause a PHP application
using the exif_read_data() function to crash or, possibly, execute
arbitrary code with the privileges of the user running that PHP
application. (CVE-2015-0232)

An integer overflow flaw leading to a heap-based buffer overflow was
found in the way PHP's FTP extension parsed file listing FTP server
responses. A malicious FTP server could use this flaw to cause a PHP
application to crash or, possibly, execute arbitrary code.
(CVE-2015-4022)

Multiple flaws were discovered in the way PHP performed object
unserialization. Specially crafted input processed by the
unserialize() function could cause a PHP application to crash or,
possibly, execute arbitrary code. (CVE-2015-0273, CVE-2015-2787,
CVE-2015-4147, CVE-2015-4148, CVE-2015-4599, CVE-2015-4600,
CVE-2015-4601, CVE-2015-4602, CVE-2015-4603)

It was found that certain PHP functions did not properly handle file
names containing a NULL character. A remote attacker could possibly
use this flaw to make a PHP script access unexpected files and bypass
intended file system access restrictions. (CVE-2015-4026,
CVE-2015-3411, CVE-2015-3412, CVE-2015-4598)

Multiple flaws were found in the way the way PHP's Phar extension
parsed Phar archives. A specially crafted archive could cause PHP to
crash or, possibly, execute arbitrary code when opened.
(CVE-2015-2301, CVE-2015-2783, CVE-2015-3307, CVE-2015-3329,
CVE-2015-4021)

A heap buffer overflow flaw was found in the
enchant_broker_request_dict() function of PHP's enchant extension. An
attacker able to make a PHP application enchant dictionaries could
possibly cause it to crash. (CVE-2014-9705)

A buffer over-read flaw was found in the GD library used by the PHP gd
extension. A specially crafted GIF file could cause a PHP application
using the imagecreatefromgif() function to crash. (CVE-2014-9709)

A double free flaw was found in zend_ts_hash_graceful_destroy()
function in the PHP ZTS module. This flaw could possibly cause a PHP
application to crash. (CVE-2014-9425)

After installing the updated packages, the httpd daemon must be
restarted for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1507&L=scientific-linux-errata&F=&S=&P=6144
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3cca39c3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"php-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-bcmath-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-cli-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-common-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-dba-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-debuginfo-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-devel-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-embedded-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-enchant-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-fpm-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-gd-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-imap-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-intl-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-ldap-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-mbstring-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-mysql-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-odbc-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pdo-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pgsql-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-process-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-pspell-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-recode-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-snmp-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-soap-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-tidy-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-xml-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-xmlrpc-5.3.3-46.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"php-zts-5.3.3-46.el6_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1135 and 
# CentOS Errata and Security Advisory 2015:1135 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(84345);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2014-8142", "CVE-2014-9652", "CVE-2014-9705", "CVE-2014-9709", "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-2301", "CVE-2015-2348", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3307", "CVE-2015-3329", "CVE-2015-3330", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4025", "CVE-2015-4026", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4604", "CVE-2015-4605", "CVE-2015-4643");
  script_bugtraq_id(71791, 72505, 72539, 72541, 72701, 73031, 73037, 73306, 73357, 73431, 73434, 74204, 74239, 74240, 74413, 74700, 74703, 74902, 74903, 74904, 75056, 75103, 75233, 75241, 75244, 75246, 75249, 75250, 75251, 75252, 75255);
  script_osvdb_id(115011, 116020, 117467, 117469, 118582, 118589, 119650, 119772, 119773, 119774, 120925, 120926, 120930, 120938, 121321, 121398, 122125, 122126, 122127, 122257, 122261, 122268, 123148, 123639, 123640, 123677);
  script_xref(name:"RHSA", value:"2015:1135");

  script_name(english:"CentOS 7 : php (CESA-2015:1135)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A flaw was found in the way the PHP module for the Apache httpd web
server handled pipelined requests. A remote attacker could use this
flaw to trigger the execution of a PHP script in a deinitialized
interpreter, causing it to crash or, possibly, execute arbitrary code.
(CVE-2015-3330)

A flaw was found in the way PHP parsed multipart HTTP POST requests. A
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
possibly, execute arbitrary code. (CVE-2014-8142, CVE-2015-0231,
CVE-2015-0273, CVE-2015-2787, CVE-2015-4147, CVE-2015-4148,
CVE-2015-4599, CVE-2015-4600, CVE-2015-4601, CVE-2015-4602,
CVE-2015-4603)

It was found that certain PHP functions did not properly handle file
names containing a NULL character. A remote attacker could possibly
use this flaw to make a PHP script access unexpected files and bypass
intended file system access restrictions. (CVE-2015-2348,
CVE-2015-4025, CVE-2015-4026, CVE-2015-3411, CVE-2015-3412,
CVE-2015-4598)

Multiple flaws were found in the way the way PHP's Phar extension
parsed Phar archives. A specially crafted archive could cause PHP to
crash or, possibly, execute arbitrary code when opened.
(CVE-2015-2301, CVE-2015-2783, CVE-2015-3307, CVE-2015-3329,
CVE-2015-4021)

Multiple flaws were found in PHP's File Information (fileinfo)
extension. A remote attacker could cause a PHP application to crash if
it used fileinfo to identify type of attacker supplied files.
(CVE-2014-9652, CVE-2015-4604, CVE-2015-4605)

A heap buffer overflow flaw was found in the
enchant_broker_request_dict() function of PHP's enchant extension. An
attacker able to make a PHP application enchant dictionaries could
possibly cause it to crash. (CVE-2014-9705)

A buffer over-read flaw was found in the GD library used by the PHP gd
extension. A specially crafted GIF file could cause a PHP application
using the imagecreatefromgif() function to crash. (CVE-2014-9709)

This update also fixes the following bugs :

* The libgmp library in some cases terminated unexpectedly with a
segmentation fault when being used with other libraries that use the
GMP memory management. With this update, PHP no longer changes libgmp
memory allocators, which prevents the described crash from occurring.
(BZ#1212305)

* When using the Open Database Connectivity (ODBC) API, the PHP
process in some cases terminated unexpectedly with a segmentation
fault. The underlying code has been adjusted to prevent this crash.
(BZ#1212299)

* Previously, running PHP on a big-endian system sometimes led to
memory corruption in the fileinfo module. This update adjusts the
behavior of the PHP pointer so that it can be freed without causing
memory corruption. (BZ#1212298)

All php users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-June/021191.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?418bf2f7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-bcmath-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-cli-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-common-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-dba-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-devel-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-embedded-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-enchant-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-fpm-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-gd-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-intl-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-ldap-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mbstring-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mysql-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-mysqlnd-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-odbc-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pdo-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pgsql-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-process-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-pspell-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-recode-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-snmp-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-soap-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-xml-5.4.16-36.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"php-xmlrpc-5.4.16-36.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

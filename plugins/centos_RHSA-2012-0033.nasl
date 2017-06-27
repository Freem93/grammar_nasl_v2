#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0033 and 
# CentOS Errata and Security Advisory 2012:0033 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57642);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2011-0708", "CVE-2011-1148", "CVE-2011-1466", "CVE-2011-1469", "CVE-2011-2202", "CVE-2011-4566", "CVE-2011-4885");
  script_bugtraq_id(46365, 46843, 46967, 46970, 48259, 49241, 50907, 51193);
  script_osvdb_id(71597, 73113, 73218, 73624, 73626, 77446, 78115);
  script_xref(name:"RHSA", value:"2012:0033");

  script_name(english:"CentOS 5 : php (CESA-2012:0033)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix several security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
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

Red Hat would like to thank oCERT for reporting CVE-2011-4885. oCERT
acknowledges Julian Walde and Alexander Klink as the original
reporters of CVE-2011-4885.

All php users should upgrade to these updated packages, which contain
backported patches to resolve these issues. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-January/018379.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a389024"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"php-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-bcmath-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-cli-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-common-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-dba-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-devel-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-gd-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-imap-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ldap-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mbstring-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mysql-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ncurses-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-odbc-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pdo-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pgsql-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-snmp-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-soap-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xml-5.1.6-27.el5_7.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xmlrpc-5.1.6-27.el5_7.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:405 and 
# CentOS Errata and Security Advisory 2005:405 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21818);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2004-1392", "CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043");
  script_osvdb_id(11196, 15183, 15184, 15629, 15630);
  script_xref(name:"RHSA", value:"2005:405");

  script_name(english:"CentOS 3 : PHP (CESA-2005:405)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix various security issues are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

A bug was found in the way PHP processes IFF and JPEG images. It is
possible to cause PHP to consume CPU resources for a short period of
time by supplying a carefully crafted IFF or JPEG image. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
names CVE-2005-0524 and CVE-2005-0525 to these issues.

A buffer overflow bug was also found in the way PHP processes EXIF
image headers. It is possible for an attacker to construct an image
file in such a way that it could execute arbitrary instructions when
processed by PHP. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1042 to this issue.

A denial of service bug was found in the way PHP processes EXIF image
headers. It is possible for an attacker to cause PHP to enter an
infinite loop for a short period of time by supplying a carefully
crafted image file to PHP for processing. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2005-1043 to this issue.

Several bug fixes are also included in this update :

  - The security fixes in RHSA-2004-687 to the
    'unserializer' code introduced some performance issues.

  - In the gd extension, the 'imagecopymerge' function did
    not correctly handle transparency. The original image
    was being obscured in the resultant image.

  - In the curl extension, safe mode was not enforced for
    'file:///' URL lookups (CVE-2004-1392).

Users of PHP should upgrade to these updated packages, which contain
backported fixes for these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011613.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9af0a4e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011614.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43a1e555"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011615.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9748b867"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"php-4.3.2-23.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-devel-4.3.2-23.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-imap-4.3.2-23.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-ldap-4.3.2-23.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-mysql-4.3.2-23.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-odbc-4.3.2-23.ent")) flag++;
if (rpm_check(release:"CentOS-3", reference:"php-pgsql-4.3.2-23.ent")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

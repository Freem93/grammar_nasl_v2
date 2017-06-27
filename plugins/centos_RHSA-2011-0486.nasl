#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0486 and 
# CentOS Errata and Security Advisory 2011:0486 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53813);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/26 15:53:26 $");

  script_cve_id("CVE-2011-1425");
  script_bugtraq_id(47135);
  script_osvdb_id(72303);
  script_xref(name:"RHSA", value:"2011:0486");

  script_name(english:"CentOS 4 / 5 : xmlsec1 (CESA-2011:0486)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xmlsec1 packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The XML Security Library is a C library based on libxml2 and OpenSSL
that implements the XML Digital Signature and XML Encryption
standards.

A flaw was found in the way xmlsec1 handled XML files that contain an
XSLT transformation specification. A specially crafted XML file could
cause xmlsec1 to create or overwrite an arbitrary file while
performing the verification of a file's digital signature.
(CVE-2011-1425)

Red Hat would like to thank Nicolas Gregoire and Aleksey Sanin for
reporting this issue.

This update also fixes the following bug :

* xmlsec1 previously used an incorrect search path when searching for
crypto plug-in libraries, possibly trying to access such libraries
using a relative path. (BZ#558480, BZ#700467)

Users of xmlsec1 should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, all running applications that use the xmlsec1 library must
be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017509.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017513.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xmlsec1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmlsec1-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xmlsec1-1.2.6-3.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xmlsec1-1.2.6-3.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xmlsec1-devel-1.2.6-3.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xmlsec1-devel-1.2.6-3.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xmlsec1-openssl-1.2.6-3.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xmlsec1-openssl-1.2.6-3.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xmlsec1-openssl-devel-1.2.6-3.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xmlsec1-openssl-devel-1.2.6-3.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"xmlsec1-1.2.9-8.1.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-devel-1.2.9-8.1.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-gnutls-1.2.9-8.1.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-gnutls-devel-1.2.9-8.1.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-nss-1.2.9-8.1.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-nss-devel-1.2.9-8.1.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-openssl-1.2.9-8.1.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-openssl-devel-1.2.9-8.1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

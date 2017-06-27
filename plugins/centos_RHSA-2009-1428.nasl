#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1428 and 
# CentOS Errata and Security Advisory 2009:1428 respectively.
#

include("compat.inc");

if (description)
{
  script_id(40894);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:43:06 $");

  script_cve_id("CVE-2009-0217");
  script_bugtraq_id(35671);
  script_xref(name:"RHSA", value:"2009:1428");

  script_name(english:"CentOS 4 / 5 : xmlsec1 (CESA-2009:1428)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xmlsec1 packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The XML Security Library is a C library based on libxml2 and OpenSSL.
It implements the XML Signature Syntax and Processing and XML
Encryption Syntax and Processing standards. HMAC is used for message
authentication using cryptographic hash functions. The HMAC algorithm
allows the hash output to be truncated (as documented in RFC 2104).

A missing check for the recommended minimum length of the truncated
form of HMAC-based XML signatures was found in xmlsec1. An attacker
could use this flaw to create a specially crafted XML file that forges
an XML signature, allowing the attacker to bypass authentication that
is based on the XML Signature specification. (CVE-2009-0217)

Users of xmlsec1 should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, applications that use the XML Security Library must
be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016290.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?022ee819"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016291.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42c2e0a9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016129.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?979c6702"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016130.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66df145f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016161.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f503edc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016162.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dde44eb0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xmlsec1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xmlsec1-1.2.6-3.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xmlsec1-1.2.6-3.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xmlsec1-devel-1.2.6-3.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xmlsec1-devel-1.2.6-3.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xmlsec1-openssl-1.2.6-3.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xmlsec1-openssl-1.2.6-3.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"xmlsec1-openssl-devel-1.2.6-3.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"xmlsec1-openssl-devel-1.2.6-3.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"xmlsec1-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-devel-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-gnutls-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-gnutls-devel-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-nss-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-nss-devel-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-openssl-1.2.9-8.1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xmlsec1-openssl-devel-1.2.9-8.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

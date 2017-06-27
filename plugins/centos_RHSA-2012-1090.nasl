#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1090 and 
# CentOS Errata and Security Advisory 2012:1090 respectively.
#

include("compat.inc");

if (description)
{
  script_id(60000);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:51 $");

  script_cve_id("CVE-2012-0441");
  script_bugtraq_id(53798);
  script_osvdb_id(82675);
  script_xref(name:"RHSA", value:"2012:1090");

  script_name(english:"CentOS 5 : nss (CESA-2012:1090)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss and nspr packages that fix two security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

A flaw was found in the way the ASN.1 (Abstract Syntax Notation One)
decoder in NSS handled zero length items. This flaw could cause the
decoder to incorrectly skip or replace certain items with a default
value, or could cause an application to crash if, for example, it
received a specially crafted OCSP (Online Certificate Status Protocol)
response. (CVE-2012-0441)

It was found that a Certificate Authority (CA) issued a subordinate CA
certificate to its customer, that could be used to issue certificates
for any name. This update renders the subordinate CA certificate as
untrusted. (BZ#798533)

Note: The BZ#798533 fix only applies to applications using the NSS
Builtin Object Token. It does not render the certificates untrusted
for applications that use the NSS library, but do not use the NSS
Builtin Object Token.

In addition, the nspr package has been upgraded to upstream version
4.9.1, and the nss package has been upgraded to upstream version
3.13.5. These updates provide a number of bug fixes and enhancements
over the previous versions. (BZ#834220, BZ#834219)

All NSS and NSPR users should upgrade to these updated packages, which
correct these issues and add these enhancements. After installing the
update, applications using NSS and NSPR must be restarted for the
changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018743.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c604ba9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");
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
if (rpm_check(release:"CentOS-5", reference:"nspr-4.9.1-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nspr-devel-4.9.1-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-3.13.5-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.13.5-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.13.5-4.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.13.5-4.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

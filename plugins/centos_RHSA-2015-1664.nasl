#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1664 and 
# CentOS Errata and Security Advisory 2015:1664 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85634);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/26 13:32:36 $");

  script_cve_id("CVE-2015-2721", "CVE-2015-2730");
  script_osvdb_id(124092, 124105);
  script_xref(name:"RHSA", value:"2015:1664");

  script_name(english:"CentOS 5 : nss (CESA-2015:1664)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss packages that fix two security issues, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 5.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications.

It was found that NSS permitted skipping of the ServerKeyExchange
packet during a handshake involving ECDHE (Elliptic Curve
Diffie-Hellman key Exchange). A remote attacker could use this flaw to
bypass the forward-secrecy of a TLS/SSL connection. (CVE-2015-2721)

A flaw was found in the way NSS verified certain ECDSA (Elliptic Curve
Digital Signature Algorithm) signatures. Under certain conditions, an
attacker could use this flaw to conduct signature forgery attacks.
(CVE-2015-2730)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Karthikeyan Bhargavan as the original
reporter of CVE-2015-2721, and Watson Ladd as the original reporter of
CVE-2015-2730.

The nss packages have been upgraded to upstream version 3.19.1, which
provides a number of bug fixes and enhancements over the previous
version.

All nss users are advised to upgrade to these updated packages, which
correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021343.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?079e87bf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"nss-3.19.1-1.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.19.1-1.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.19.1-1.el5_11")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.19.1-1.el5_11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

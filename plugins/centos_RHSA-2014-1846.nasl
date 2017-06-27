#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1846 and 
# CentOS Errata and Security Advisory 2014:1846 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79220);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/11/24 11:36:26 $");

  script_cve_id("CVE-2014-8564");
  script_bugtraq_id(71003);
  script_xref(name:"RHSA", value:"2014:1846");

  script_name(english:"CentOS 7 : gnutls (CESA-2014:1846)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix one security issue are now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS). The gnutls
packages also include the libtasn1 library, which provides Abstract
Syntax Notation One (ASN.1) parsing and structures management, and
Distinguished Encoding Rules (DER) encoding and decoding functions.

An out-of-bounds memory write flaw was found in the way GnuTLS parsed
certain ECC (Elliptic Curve Cryptography) certificates or certificate
signing requests (CSR). A malicious user could create a specially
crafted ECC certificate or a certificate signing request that, when
processed by an application compiled against GnuTLS (for example,
certtool), could cause that application to crash or execute arbitrary
code with the permissions of the user running the application.
(CVE-2014-8564)

Red Hat would like to thank GnuTLS upstream for reporting this issue.
Upstream acknowledges Sean Burford as the original reporter.

All gnutls users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. For the update
to take effect, all applications linked to the GnuTLS or libtasn1
library must be restarted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-November/020756.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c846035"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-dane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnutls-3.1.18-10.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnutls-c++-3.1.18-10.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnutls-dane-3.1.18-10.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnutls-devel-3.1.18-10.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnutls-utils-3.1.18-10.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

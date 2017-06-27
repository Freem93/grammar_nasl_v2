#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0165 and 
# CentOS Errata and Security Advisory 2010:0165 respectively.
#

include("compat.inc");

if (description)
{
  script_id(45364);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:13:12 $");

  script_cve_id("CVE-2009-3555");
  script_osvdb_id(61234, 62064);
  script_xref(name:"RHSA", value:"2010:0165");

  script_name(english:"CentOS 4 / 5 : nss (CESA-2010:0165)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss packages that fix a security issue are now available for
Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSLv2,
SSLv3, TLS, and other security standards.

Netscape Portable Runtime (NSPR) provides platform independence for
non-GUI operating system facilities. These facilities include threads,
thread synchronization, normal file and network I/O, interval timing,
calendar time, basic memory management (malloc and free), and shared
library linking.

A flaw was found in the way the TLS/SSL (Transport Layer
Security/Secure Sockets Layer) protocols handled session
renegotiation. A man-in-the-middle attacker could use this flaw to
prefix arbitrary plain text to a client's session (for example, an
HTTPS connection to a website). This could force the server to process
an attacker's request as if authenticated using the victim's
credentials. This update addresses this flaw by implementing the TLS
Renegotiation Indication Extension, as defined in RFC 5746.
(CVE-2009-3555)

Refer to the following Knowledgebase article for additional details
about this flaw: http://kbase.redhat.com/faq/docs/DOC-20491

Users of Red Hat Certificate System 7.3 and 8.0 should review the
following Knowledgebase article before installing this update:
http://kbase.redhat.com/faq/docs/DOC-28439

All users of NSS are advised to upgrade to these updated packages,
which update NSS to version 3.12.6. This erratum also updates the NSPR
packages to the version required by NSS 3.12.6. All running
applications using the NSS library must be restarted for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016601.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3bd16853"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016602.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea3afc43"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016607.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95e18529"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-March/016608.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4084b3f4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nspr-4.8.4-1.1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nspr-4.8.4-1.1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nspr-devel-4.8.4-1.1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nspr-devel-4.8.4-1.1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-3.12.6-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-3.12.6-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-devel-3.12.6-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-devel-3.12.6-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nss-tools-3.12.6-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nss-tools-3.12.6-1.el4_8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"nspr-4.8.4-1.el5_4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nspr-devel-4.8.4-1.el5_4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-3.12.6-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-devel-3.12.6-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-pkcs11-devel-3.12.6-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nss-tools-3.12.6-1.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0492 and 
# CentOS Errata and Security Advisory 2008:0492 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43689);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-1948", "CVE-2008-1949", "CVE-2008-1950");
  script_bugtraq_id(29292);
  script_osvdb_id(45382, 45383, 45384);
  script_xref(name:"RHSA", value:"2008:0492");

  script_name(english:"CentOS 4 : gnutls (CESA-2008:0492)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The GnuTLS Library provides support for cryptographic algorithms and
protocols such as TLS. GnuTLS includes libtasn1, a library developed
for ASN.1 structures management that includes DER encoding and
decoding.

Flaws were found in the way GnuTLS handles malicious client
connections. A malicious remote client could send a specially crafted
request to a service using GnuTLS that could cause the service to
crash. (CVE-2008-1948, CVE-2008-1949, CVE-2008-1950)

We believe it is possible to leverage the flaw CVE-2008-1948 to
execute arbitrary code but have been unable to prove this at the time
of releasing this advisory. Red Hat Enterprise Linux 4 does not ship
with any applications directly affected by this flaw. Third-party
software which runs on Red Hat Enterprise Linux 4 could, however, be
affected by this vulnerability. Consequently, we have assigned it
important severity.

Users of GnuTLS are advised to upgrade to these updated packages,
which contain a backported patch that corrects these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014927.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014935.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gnutls-1.0.20-4.el4_6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gnutls-1.0.20-4.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gnutls-1.0.20-4.el4_6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gnutls-devel-1.0.20-4.el4_6")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gnutls-devel-1.0.20-4.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gnutls-devel-1.0.20-4.el4_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

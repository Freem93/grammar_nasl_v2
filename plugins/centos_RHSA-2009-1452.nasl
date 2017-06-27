#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1452 and 
# CentOS Errata and Security Advisory 2009:1452 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43792);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-2473", "CVE-2009-2474");
  script_bugtraq_id(36079, 36080);
  script_xref(name:"RHSA", value:"2009:1452");

  script_name(english:"CentOS 4 / 5 : neon (CESA-2009:1452)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated neon packages that fix two security issues are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

neon is an HTTP and WebDAV client library, with a C interface. It
provides a high-level interface to HTTP and WebDAV methods along with
a low-level interface for HTTP request handling. neon supports
persistent connections, proxy servers, basic, digest and Kerberos
authentication, and has complete SSL support.

It was discovered that neon is affected by the previously published
'null prefix attack', caused by incorrect handling of NULL characters
in X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority, the attacker could use the certificate during a
man-in-the-middle attack and potentially confuse an application using
the neon library into accepting it by mistake. (CVE-2009-2474)

A denial of service flaw was found in the neon Extensible Markup
Language (XML) parser. A remote attacker (malicious DAV server) could
provide a specially crafted XML document that would cause excessive
memory and CPU consumption if an application using the neon XML parser
was tricked into processing it. (CVE-2009-2473)

All neon users should upgrade to these updated packages, which contain
backported patches to correct these issues. Applications using the
neon HTTP and WebDAV client library, such as cadaver, must be
restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016252.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fde7ca60"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016253.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7513e184"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016167.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b675c197"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016168.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0728c801"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected neon packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:neon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:neon-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"neon-0.24.7-4.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"neon-0.24.7-4.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"neon-devel-0.24.7-4.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"neon-devel-0.24.7-4.el4_8.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"neon-0.25.5-10.el5_4.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"neon-devel-0.25.5-10.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:582 and 
# CentOS Errata and Security Advisory 2005:582 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21843);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1268", "CVE-2005-2088");
  script_osvdb_id(17738, 18286);
  script_xref(name:"RHSA", value:"2005:582");

  script_name(english:"CentOS 3 / 4 : httpd (CESA-2005:582)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages to correct two security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a powerful, full-featured, efficient, and
freely-available Web server.

Watchfire reported a flaw that occured when using the Apache server as
an HTTP proxy. A remote attacker could send an HTTP request with both
a 'Transfer-Encoding: chunked' header and a 'Content-Length' header.
This caused Apache to incorrectly handle and forward the body of the
request in a way that the receiving server processes it as a separate
HTTP request. This could allow the bypass of Web application firewall
protection or lead to cross-site scripting (XSS) attacks. The Common
Vulnerabilities and Exposures project (cve.mitre.org) assigned the
name CVE-2005-2088 to this issue.

Marc Stern reported an off-by-one overflow in the mod_ssl CRL
verification callback. In order to exploit this issue the Apache
server would need to be configured to use a malicious certificate
revocation list (CRL). The Common Vulnerabilities and Exposures
project (cve.mitre.org) assigned the name CVE-2005-1268 to this issue.

Users of Apache httpd should update to these errata packages that
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011977.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1d88775"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011978.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0572800b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011979.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11d91a19"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011980.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?387a2532"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011989.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91f00df3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011993.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc947489"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/26");
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
if (rpm_check(release:"CentOS-3", reference:"httpd-2.0.46-46.2.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"httpd-devel-2.0.46-46.2.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mod_ssl-2.0.46-46.2.ent.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"httpd-2.0.52-12.1.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-devel-2.0.52-12.1.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-manual-2.0.52-12.1.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-suexec-2.0.52-12.1.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mod_ssl-2.0.52-12.1.ent.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

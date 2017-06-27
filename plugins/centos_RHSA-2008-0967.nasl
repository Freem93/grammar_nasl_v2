#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0967 and 
# CentOS Errata and Security Advisory 2008:0967 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(37062);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-2364", "CVE-2008-2939");
  script_bugtraq_id(29653, 30560);
  script_xref(name:"RHSA", value:"2008:0967");

  script_name(english:"CentOS 3 / 4 / 5 : httpd (CESA-2008:0967)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that resolve several security issues and fix a
bug are now available for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

A flaw was found in the mod_proxy Apache module. An attacker in
control of a Web server to which requests were being proxied could
have caused a limited denial of service due to CPU consumption and
stack exhaustion. (CVE-2008-2364)

A flaw was found in the mod_proxy_ftp Apache module. If Apache was
configured to support FTP-over-HTTP proxying, a remote attacker could
have performed a cross-site scripting attack. (CVE-2008-2939)

In addition, these updated packages fix a bug found in the handling of
the 'ProxyRemoteMatch' directive in the Red Hat Enterprise Linux 4
httpd packages. This bug is not present in the Red Hat Enterprise
Linux 3 or Red Hat Enterprise Linux 5 packages.

Users of httpd should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015395.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd1dc880"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015396.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df8f5c5a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015399.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3cab56e3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015400.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1ae578f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015404.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?951497f3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015410.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?704de9f5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?581c6865"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a87857d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"httpd-2.0.46-71.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", reference:"httpd-devel-2.0.46-71.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mod_ssl-2.0.46-71.ent.centos")) flag++;

if (rpm_check(release:"CentOS-4", reference:"httpd-2.0.52-41.ent.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-devel-2.0.52-41.ent.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-manual-2.0.52-41.ent.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-suexec-2.0.52-41.ent.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mod_ssl-2.0.52-41.ent.2.centos4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-11.el5_2.centos.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-11.el5_2.centos.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-11.el5_2.centos.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-11.el5_2.centos.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

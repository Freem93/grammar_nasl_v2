#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:608 and 
# CentOS Errata and Security Advisory 2005:608 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21845);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2700", "CVE-2005-2728");
  script_osvdb_id(18977, 19188);
  script_xref(name:"RHSA", value:"2005:608");

  script_name(english:"CentOS 3 / 4 : httpd (CESA-2005:608)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages that correct two security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular and freely-available Web server.

A flaw was discovered in mod_ssl's handling of the 'SSLVerifyClient'
directive. This flaw occurs if a virtual host is configured using
'SSLVerifyClient optional' and a directive 'SSLVerifyClient required'
is set for a specific location. For servers configured in this
fashion, an attacker may be able to access resources that should
otherwise be protected, by not supplying a client certificate when
connecting. The Common Vulnerabilities and Exposures project assigned
the name CVE-2005-2700 to this issue.

A flaw was discovered in Apache httpd where the byterange filter would
buffer certain responses into memory. If a server has a dynamic
resource such as a CGI script or PHP script that generates a large
amount of data, an attacker could send carefully crafted requests in
order to consume resources, potentially leading to a Denial of
Service. (CVE-2005-2728)

Users of Apache httpd should update to these errata packages that
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012113.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2841c91c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012114.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f62615e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012117.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7fbb5c6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d6dab32"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012119.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5442ce57"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05486719"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/25");
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
if (rpm_check(release:"CentOS-3", reference:"httpd-2.0.46-46.3.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"httpd-devel-2.0.46-46.3.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mod_ssl-2.0.46-46.3.ent.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"httpd-2.0.52-12.2.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-devel-2.0.52-12.2.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-manual-2.0.52-12.2.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-suexec-2.0.52-12.2.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mod_ssl-2.0.52-12.2.ent.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

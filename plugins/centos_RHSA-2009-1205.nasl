#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1205 and 
# CentOS Errata and Security Advisory 2009:1205 respectively.
#

include("compat.inc");

if (description)
{
  script_id(40532);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-1891", "CVE-2009-2412");
  script_bugtraq_id(35623, 35949);
  script_xref(name:"RHSA", value:"2009:1205");

  script_name(english:"CentOS 3 : httpd (CESA-2009:1205)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix multiple security issues and a bug are
now available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server. The httpd package
shipped with Red Hat Enterprise Linux 3 contains embedded copies of
the Apache Portable Runtime (APR) libraries, which provide a free
library of C data structures and routines, and also additional utility
interfaces to support XML parsing, LDAP, database interfaces, URI
parsing, and more.

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the way the Apache Portable Runtime (APR)
manages memory pool and relocatable memory allocations. An attacker
could use these flaws to issue a specially crafted request for memory
allocation, which would lead to a denial of service (application
crash) or, potentially, execute arbitrary code with the privileges of
an application using the APR libraries. (CVE-2009-2412)

A denial of service flaw was found in the Apache mod_deflate module.
This module continued to compress large files until compression was
complete, even if the network connection that requested the content
was closed before compression completed. This would cause mod_deflate
to consume large amounts of CPU if mod_deflate was enabled for a large
file. (CVE-2009-1891)

This update also fixes the following bug :

* in some cases the Content-Length header was dropped from HEAD
responses. This resulted in certain sites not working correctly with
mod_proxy, such as www.windowsupdate.com. (BZ#506016)

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016066.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef7d7786"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016067.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e1bba03"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"httpd-2.0.46-75.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"httpd-2.0.46-75.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"httpd-devel-2.0.46-75.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"httpd-devel-2.0.46-75.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"mod_ssl-2.0.46-75.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"mod_ssl-2.0.46-75.ent.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1204 and 
# CentOS Errata and Security Advisory 2009:1204 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43776);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2009-2412");
  script_bugtraq_id(35949);
  script_xref(name:"RHSA", value:"2009:1204");

  script_name(english:"CentOS 5 : apr (CESA-2009:1204)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated apr and apr-util packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache Portable Runtime (APR) is a portability library used by the
Apache HTTP Server and other projects. It aims to provide a free
library of C data structures and routines. apr-util is a utility
library used with APR. This library provides additional utility
interfaces for APR; including support for XML parsing, LDAP, database
interfaces, URI parsing, and more.

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the way the Apache Portable Runtime (APR)
manages memory pool and relocatable memory allocations. An attacker
could use these flaws to issue a specially crafted request for memory
allocation, which would lead to a denial of service (application
crash) or, potentially, execute arbitrary code with the privileges of
an application using the APR libraries. (CVE-2009-2412)

All apr and apr-util users should upgrade to these updated packages,
which contain backported patches to correct these issues. Applications
using the APR libraries, such as httpd, must be restarted for this
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016072.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5577ee06"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016073.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e81c411"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected apr packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-util-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"apr-1.2.7-11.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-devel-1.2.7-11.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-docs-1.2.7-11.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-util-1.2.7-7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-util-devel-1.2.7-7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-util-docs-1.2.7-7.el5_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0474 and 
# CentOS Errata and Security Advisory 2014:0474 respectively.
#

include("compat.inc");

if (description)
{
  script_id(73922);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2014-0114");
  script_bugtraq_id(67121);
  script_osvdb_id(106409);
  script_xref(name:"RHSA", value:"2014:0474");

  script_name(english:"CentOS 5 : struts (CESA-2014:0474)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated struts packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Apache Struts is a framework for building web applications with Java.

It was found that the Struts 1 ActionForm object allowed access to the
'class' parameter, which is directly mapped to the getClass() method.
A remote attacker could use this flaw to manipulate the ClassLoader
used by an application server running Struts 1. This could lead to
remote code execution under certain conditions. (CVE-2014-0114)

All struts users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. All running
applications using struts must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2014-May/020284.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected struts packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:struts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:struts-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:struts-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:struts-webapps-tomcat5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"struts-1.2.9-4jpp.8.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"struts-javadoc-1.2.9-4jpp.8.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"struts-manual-1.2.9-4jpp.8.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"struts-webapps-tomcat5-1.2.9-4jpp.8.el5_10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

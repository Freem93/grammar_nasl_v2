#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0492 and 
# CentOS Errata and Security Advisory 2016:0492 respectively.
#

include("compat.inc");

if (description)
{
  script_id(90121);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:07 $");

  script_cve_id("CVE-2014-7810");
  script_osvdb_id(122158);
  script_xref(name:"RHSA", value:"2016:0492");

  script_name(english:"CentOS 6 : tomcat6 (CESA-2016:0492)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat6 packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

It was found that the expression language resolver evaluated
expressions within a privileged code section. A malicious web
application could use this flaw to bypass security manager
protections. (CVE-2014-7810)

This update also fixes the following bug :

* Previously, using a New I/O (NIO) connector in the Apache Tomcat 6
servlet resulted in a large memory leak. An upstream patch has been
applied to fix this bug, and the memory leak no longer occurs.
(BZ#1301646)

All Tomcat 6 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. Tomcat must
be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-March/021766.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec231ee4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"tomcat6-6.0.24-94.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-admin-webapps-6.0.24-94.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-docs-webapp-6.0.24-94.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-el-2.1-api-6.0.24-94.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-javadoc-6.0.24-94.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-jsp-2.1-api-6.0.24-94.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-lib-6.0.24-94.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-servlet-2.5-api-6.0.24-94.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-webapps-6.0.24-94.el6_7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

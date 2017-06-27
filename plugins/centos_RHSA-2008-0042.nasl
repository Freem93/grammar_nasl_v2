#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0042 and 
# CentOS Errata and Security Advisory 2008:0042 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43669);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-5342", "CVE-2007-5461");
  script_bugtraq_id(26070, 27006);
  script_osvdb_id(38187, 39833);
  script_xref(name:"RHSA", value:"2008:0042");

  script_name(english:"CentOS 5 : tomcat (CESA-2008:0042)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat packages that fix security issues and bugs are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Tomcat is a servlet container for Java Servlet and JavaServer Pages
technologies.

A directory traversal vulnerability existed in the Apache Tomcat
webdav servlet. In some configurations it allowed remote authenticated
users to read files accessible to the local tomcat process.
(CVE-2007-5461)

The default security policy in the JULI logging component did not
restrict access permissions to files. This could be misused by
untrusted web applications to access and write arbitrary files in the
context of the tomcat process. (CVE-2007-5342)

Users of Tomcat should update to these errata packages, which contain
backported patches and are not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014764.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?601f304a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014765.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0143e7bd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/14");
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
if (rpm_check(release:"CentOS-5", reference:"tomcat5-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-admin-webapps-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-common-lib-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jasper-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-server-lib-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.3.0.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-webapps-5.5.23-0jpp.3.0.3.el5_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

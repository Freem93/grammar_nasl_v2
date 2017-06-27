#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1164 and 
# CentOS Errata and Security Advisory 2009:1164 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43770);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2007-5333", "CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783", "CVE-2009-2696");
  script_bugtraq_id(27706, 35193, 35196, 35263, 35416);
  script_xref(name:"RHSA", value:"2009:1164");

  script_name(english:"CentOS 5 : tomcat (CESA-2009:1164)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat packages that fix several security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

It was discovered that the Red Hat Security Advisory RHSA-2007:0871
did not address all possible flaws in the way Tomcat handles certain
characters and character sequences in cookie values. A remote attacker
could use this flaw to obtain sensitive information, such as session
IDs, and then use this information for session hijacking attacks.
(CVE-2007-5333)

Note: The fix for the CVE-2007-5333 flaw changes the default cookie
processing behavior: with this update, version 0 cookies that contain
values that must be quoted to be valid are automatically changed to
version 1 cookies. To reactivate the previous, but insecure behavior,
add the following entry to the '/etc/tomcat5/catalina.properties' 
file :

org.apache.tomcat.util.http.ServerCookie.VERSION_SWITCH=false

It was discovered that request dispatchers did not properly normalize
user requests that have trailing query strings, allowing remote
attackers to send specially crafted requests that would cause an
information leak. (CVE-2008-5515)

A flaw was found in the way the Tomcat AJP (Apache JServ Protocol)
connector processes AJP connections. An attacker could use this flaw
to send specially crafted requests that would cause a temporary denial
of service. (CVE-2009-0033)

It was discovered that the error checking methods of certain
authentication classes did not have sufficient error checking,
allowing remote attackers to enumerate (via brute-force methods)
usernames registered with applications running on Tomcat when
FORM-based authentication was used. (CVE-2009-0580)

A cross-site scripting (XSS) flaw was found in the examples calendar
application. With some web browsers, remote attackers could use this
flaw to inject arbitrary web script or HTML via the 'time' parameter.
(CVE-2009-0781)

It was discovered that web applications containing their own XML
parsers could replace the XML parser Tomcat uses to parse
configuration files. A malicious web application running on a Tomcat
instance could read or, potentially, modify the configuration and
XML-based data of other web applications deployed on the same Tomcat
instance. (CVE-2009-0783)

Users of Tomcat should upgrade to these updated packages, which
contain backported patches to resolve these issues. Tomcat must be
restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-July/016048.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d67e20a3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-July/016049.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a2fc310"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 22, 79, 200);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/29");
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
if (rpm_check(release:"CentOS-5", reference:"tomcat5-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-admin-webapps-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-common-lib-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jasper-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-server-lib-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tomcat5-webapps-5.5.23-0jpp.7.el5_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

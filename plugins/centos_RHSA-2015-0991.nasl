#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0991 and 
# CentOS Errata and Security Advisory 2015:0991 respectively.
#

include("compat.inc");

if (description)
{
  script_id(83380);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2014-0227");
  script_bugtraq_id(72717);
  script_osvdb_id(118214);
  script_xref(name:"RHSA", value:"2015:0991");

  script_name(english:"CentOS 6 : tomcat6 (CESA-2015:0991)");
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

It was discovered that the ChunkedInputFilter in Tomcat did not fail
subsequent attempts to read input after malformed chunked encoding was
detected. A remote attacker could possibly use this flaw to make
Tomcat process part of the request body as new request, or cause a
denial of service. (CVE-2014-0227)

This update also fixes the following bug :

* Before this update, the tomcat6 init script did not try to kill the
tomcat process if an attempt to stop it was unsuccessful, which would
prevent tomcat from restarting properly. The init script was modified
to correct this issue. (BZ#1207048)

All Tomcat 6 users are advised to upgrade to these updated packages,
which correct these issues. Tomcat must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2015-May/021105.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"tomcat6-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-admin-webapps-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-docs-webapp-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-el-2.1-api-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-javadoc-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-jsp-2.1-api-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-lib-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-servlet-2.5-api-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tomcat6-webapps-6.0.24-83.el6_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

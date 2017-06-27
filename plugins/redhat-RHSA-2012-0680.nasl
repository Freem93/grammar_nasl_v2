#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0680. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78924);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2011-1184", "CVE-2011-2204", "CVE-2011-2526", "CVE-2011-3190", "CVE-2011-4858", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064", "CVE-2012-0022");
  script_bugtraq_id(48456, 48667, 49353, 49762, 51200, 51447);
  script_osvdb_id(73429, 73797, 73798, 74818, 76189, 78113, 78331, 78483, 78573, 78598, 78599, 78600);
  script_xref(name:"RHSA", value:"2012:0680");

  script_name(english:"RHEL 5 / 6 : JBoss Web Server (RHSA-2012:0680)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat5 packages that fix multiple security issues and two
bugs are now available for JBoss Enterprise Web Server 1.0.2 for Red
Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

JBoss Enterprise Web Server includes the Tomcat Native library,
providing Apache Portable Runtime (APR) support for Tomcat. References
in this text to APR refer to the Tomcat Native implementation, not any
other apr package.

This update includes bug fixes as documented in JBPAPP-4873 and
JBPAPP-6133. It also resolves the following security issues :

Multiple flaws were found in the way Tomcat handled HTTP DIGEST
authentication. These flaws weakened the Tomcat HTTP DIGEST
authentication implementation, subjecting it to some of the weaknesses
of HTTP BASIC authentication, for example, allowing remote attackers
to perform session replay attacks. (CVE-2011-1184, CVE-2011-5062,
CVE-2011-5063, CVE-2011-5064)

A flaw was found in the way the Coyote
(org.apache.coyote.ajp.AjpProcessor) and APR
(org.apache.coyote.ajp.AjpAprProcessor) Tomcat AJP (Apache JServ
Protocol) connectors processed certain POST requests. An attacker
could send a specially crafted request that would cause the connector
to treat the message body as a new request. This allows arbitrary AJP
messages to be injected, possibly allowing an attacker to bypass a web
application's authentication checks and gain access to information
they would otherwise be unable to access. The JK
(org.apache.jk.server.JkCoyoteHandler) connector is used by default
when the APR libraries are not present. The JK connector is not
affected by this flaw. (CVE-2011-3190)

It was found that the Java hashCode() method implementation was
susceptible to predictable hash collisions. A remote attacker could
use this flaw to cause Tomcat to use an excessive amount of CPU time
by sending an HTTP request with a large number of parameters whose
names map to the same hash value. This update introduces a limit on
the number of parameters processed per request to mitigate this issue.
The default limit is 512 for parameters and 128 for headers. These
defaults can be changed by setting the
org.apache.tomcat.util.http.Parameters.MAX_COUNT and
org.apache.tomcat.util.http.MimeHeaders.MAX_COUNT system properties.
(CVE-2011-4858)

It was found that Tomcat did not handle large numbers of parameters
and large parameter values efficiently. A remote attacker could make
Tomcat use an excessive amount of CPU time by sending an HTTP request
containing a large number of parameters or large parameter values.
This update introduces limits on the number of parameters and headers
processed per request to address this issue. Refer to the
CVE-2011-4858 description for information about the
org.apache.tomcat.util.http.Parameters.MAX_COUNT and
org.apache.tomcat.util.http.MimeHeaders.MAX_COUNT system properties.
(CVE-2012-0022)

A flaw was found in the Tomcat MemoryUserDatabase. If a runtime
exception occurred when creating a new user with a JMX client, that
user's password was logged to Tomcat log files. Note: By default, only
administrators have access to such log files. (CVE-2011-2204)

A flaw was found in the way Tomcat handled sendfile request attributes
when using the HTTP APR or NIO (Non-Blocking I/O) connector. A
malicious web application running on a Tomcat instance could use this
flaw to bypass security manager restrictions and gain access to files
it would otherwise be unable to access, or possibly terminate the Java
Virtual Machine (JVM). The HTTP NIO connector is used by default in
JBoss Enterprise Web Server. (CVE-2011-2526)

Red Hat would like to thank oCERT for reporting CVE-2011-4858, and the
Apache Tomcat project for reporting CVE-2011-2526. oCERT acknowledges
Julian Walde and Alexander Klink as the original reporters of
CVE-2011-4858.

Users of Tomcat should upgrade to these updated packages, which
resolve these issues. Tomcat must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tomcat.apache.org/security-5.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://issues.jboss.org/browse/JBPAPP-4873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://issues.jboss.org/browse/JBPAPP-6133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:0680.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3190.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2204.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-5062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-5063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-5064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4858.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0022.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper-eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0680";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;

  if (! (rpm_exists(release:"RHEL5", rpm:"mod_cluster") || rpm_exists(release:"RHEL6", rpm:"mod_cluster"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss Web Server");

  if (rpm_check(release:"RHEL5", reference:"tomcat5-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-admin-webapps-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-common-lib-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-jasper-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-jasper-eclipse-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-jasper-javadoc-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-jsp-2.0-api-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-parent-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-server-lib-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-servlet-2.4-api-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.33-27_patch_07.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"tomcat5-webapps-5.5.33-27_patch_07.ep5.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"tomcat5-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-admin-webapps-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-common-lib-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-jasper-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-jasper-eclipse-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-jasper-javadoc-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-jsp-2.0-api-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-parent-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-server-lib-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-servlet-2.4-api-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.33-28_patch_07.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"tomcat5-webapps-5.5.33-28_patch_07.ep5.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat5 / tomcat5-admin-webapps / tomcat5-common-lib / etc");
  }
}

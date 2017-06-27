#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0074. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64022);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/05 16:04:20 $");

  script_cve_id("CVE-2011-1184", "CVE-2011-2526", "CVE-2011-4610", "CVE-2011-4858", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064", "CVE-2012-0022");
  script_osvdb_id(73797, 73798, 76189, 78113, 78483, 78573, 78598, 78599, 78600, 78775);
  script_xref(name:"RHSA", value:"2012:0074");

  script_name(english:"RHEL 4 / 5 / 6 : jbossweb (RHSA-2012:0074)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated jbossweb packages that fix multiple security issues are now
available for JBoss Enterprise Application Platform 5.1.2 for Red Hat
Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

JBoss Web is the web container, based on Apache Tomcat, in JBoss
Enterprise Application Platform. It provides a single deployment
platform for the JavaServer Pages (JSP) and Java Servlet technologies.

A flaw was found in the way JBoss Web handled UTF-8 surrogate pair
characters. If JBoss Web was hosting an application with UTF-8
character encoding enabled, or that included user-supplied UTF-8
strings in a response, a remote attacker could use this flaw to cause
a denial of service (infinite loop) on the JBoss Web server.
(CVE-2011-4610)

It was found that the Java hashCode() method implementation was
susceptible to predictable hash collisions. A remote attacker could
use this flaw to cause JBoss Web to use an excessive amount of CPU
time by sending an HTTP request with a large number of parameters
whose names map to the same hash value. This update introduces a limit
on the number of parameters and headers processed per request to
mitigate this issue. The default limit is 512 for parameters and 128
for headers. These defaults can be changed by setting the
org.apache.tomcat.util.http.Parameters.MAX_COUNT and
org.apache.tomcat.util.http.MimeHeaders.MAX_COUNT system properties in
'jboss-as/server/[PROFILE]/deploy/properties-service.xml'.
(CVE-2011-4858)

It was found that JBoss Web did not handle large numbers of parameters
and large parameter values efficiently. A remote attacker could make a
JBoss Web server use an excessive amount of CPU time by sending an
HTTP request containing a large number of parameters or large
parameter values. This update introduces limits on the number of
parameters and headers processed per request to address this issue.
Refer to the CVE-2011-4858 description for information about the
org.apache.tomcat.util.http.Parameters.MAX_COUNT and
org.apache.tomcat.util.http.MimeHeaders.MAX_COUNT system properties.
(CVE-2012-0022)

Multiple flaws were found in the way JBoss Web handled HTTP DIGEST
authentication. These flaws weakened the JBoss Web HTTP DIGEST
authentication implementation, subjecting it to some of the weaknesses
of HTTP BASIC authentication, for example, allowing remote attackers
to perform session replay attacks. (CVE-2011-1184, CVE-2011-5062,
CVE-2011-5063, CVE-2011-5064)

A flaw was found in the way JBoss Web handled sendfile request
attributes when using the HTTP APR (Apache Portable Runtime) or NIO
(Non-Blocking I/O) connector. A malicious web application running on a
JBoss Web instance could use this flaw to bypass security manager
restrictions and gain access to files it would otherwise be unable to
access, or possibly terminate the Java Virtual Machine (JVM).
(CVE-2011-2526)

Red Hat would like to thank NTT OSSC for reporting CVE-2011-4610;
oCERT for reporting CVE-2011-4858; and the Apache Tomcat project for
reporting CVE-2011-2526. oCERT acknowledges Julian Walde and
Alexander Klink as the original reporters of CVE-2011-4858.

Warning: Before applying this update, back up your JBoss Enterprise
Application Platform's 'jboss-as/server/[PROFILE]/deploy/' directory,
along with all other customized configuration files.

Users of JBoss Enterprise Application Platform 5.1.2 on Red Hat
Enterprise Linux 4, 5, and 6 should upgrade to these updated packages,
which correct these issues. The JBoss server process must be restarted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4610.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4858.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0074.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-el-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0074";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL4", reference:"jbossweb-2.1.12-3_patch_03.2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-el-1.0-api-2.1.12-3_patch_03.2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-jsp-2.1-api-2.1.12-3_patch_03.2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-lib-2.1.12-3_patch_03.2.ep5.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-servlet-2.5-api-2.1.12-3_patch_03.2.ep5.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"jbossweb-2.1.12-3_patch_03.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-el-1.0-api-2.1.12-3_patch_03.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-jsp-2.1-api-2.1.12-3_patch_03.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-lib-2.1.12-3_patch_03.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-servlet-2.5-api-2.1.12-3_patch_03.2.ep5.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"jbossweb-2.1.12-3_patch_03.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-el-1.0-api-2.1.12-3_patch_03.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-jsp-2.1-api-2.1.12-3_patch_03.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-lib-2.1.12-3_patch_03.2.ep5.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jbossweb-servlet-2.5-api-2.1.12-3_patch_03.2.ep5.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jbossweb / jbossweb-el-1.0-api / jbossweb-jsp-2.1-api / etc");
  }
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1845 and 
# Oracle Linux Security Advisory ELSA-2011-1845 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68410);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:07:14 $");

  script_cve_id("CVE-2010-3718", "CVE-2011-0013", "CVE-2011-1184", "CVE-2011-2204", "CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064");
  script_bugtraq_id(46174, 46177, 48456, 49762);
  script_osvdb_id(71557, 71558, 73429, 76189, 78598, 78599, 78600);
  script_xref(name:"RHSA", value:"2011:1845");

  script_name(english:"Oracle Linux 5 : tomcat5 (ELSA-2011-1845)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1845 :

Updated tomcat5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

It was found that web applications could modify the location of the
Tomcat host's work directory. As web applications deployed on Tomcat
have read and write access to this directory, a malicious web
application could use this flaw to trick Tomcat into giving it read
and write access to an arbitrary directory on the file system.
(CVE-2010-3718)

A cross-site scripting (XSS) flaw was found in the Manager
application, used for managing web applications on Apache Tomcat. A
malicious web application could use this flaw to conduct an XSS
attack, leading to arbitrary web script execution with the privileges
of victims who are logged into and viewing Manager application web
pages. (CVE-2011-0013)

Multiple flaws were found in the way Tomcat handled HTTP DIGEST
authentication. These flaws weakened the Tomcat HTTP DIGEST
authentication implementation, subjecting it to some of the weaknesses
of HTTP BASIC authentication, for example, allowing remote attackers
to perform session replay attacks. (CVE-2011-1184)

A flaw was found in the Tomcat MemoryUserDatabase. If a runtime
exception occurred when creating a new user with a JMX client, that
user's password was logged to Tomcat log files. Note: By default, only
administrators have access to such log files. (CVE-2011-2204)

Users of Tomcat should upgrade to these updated packages, which
contain backported patches to correct these issues. Tomcat must be
restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-December/002527.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"tomcat5-5.5.23-0jpp.22.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"tomcat5-admin-webapps-5.5.23-0jpp.22.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"tomcat5-common-lib-5.5.23-0jpp.22.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"tomcat5-jasper-5.5.23-0jpp.22.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.22.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.22.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.22.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"tomcat5-server-lib-5.5.23-0jpp.22.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.22.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.22.el5_7")) flag++;
if (rpm_check(release:"EL5", reference:"tomcat5-webapps-5.5.23-0jpp.22.el5_7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat5 / tomcat5-admin-webapps / tomcat5-common-lib / etc");
}

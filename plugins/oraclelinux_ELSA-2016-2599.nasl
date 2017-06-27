#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:2599 and 
# Oracle Linux Security Advisory ELSA-2016-2599 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(94718);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/12/07 21:08:18 $");

  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763", "CVE-2016-3092");
  script_osvdb_id(134823, 134824, 134825, 134826, 134828, 134829, 140354);
  script_xref(name:"RHSA", value:"2016:2599");

  script_name(english:"Oracle Linux 7 : tomcat (ELSA-2016-2599)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:2599 :

An update for tomcat is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

The following packages have been upgraded to a newer upstream version:
tomcat (7.0.69). (BZ#1287928)

Security Fix(es) :

* A CSRF flaw was found in Tomcat's the index pages for the Manager
and Host Manager applications. These applications included a valid
CSRF token when issuing a redirect as a result of an unauthenticated
request to the root of the web application. This token could then be
used by an attacker to perform a CSRF attack. (CVE-2015-5351)

* It was found that several Tomcat session persistence mechanisms
could allow a remote, authenticated user to bypass intended
SecurityManager restrictions and execute arbitrary code in a
privileged context via a web application that placed a crafted object
in a session. (CVE-2016-0714)

* A security manager bypass flaw was found in Tomcat that could allow
remote, authenticated users to access arbitrary application data,
potentially resulting in a denial of service. (CVE-2016-0763)

* A denial of service vulnerability was identified in Commons
FileUpload that occurred when the length of the multipart boundary was
just below the size of the buffer (4096 bytes) used to read the
uploaded file if the boundary was the typical tens of bytes long.
(CVE-2016-3092)

* A directory traversal flaw was found in Tomcat's RequestUtil.java. A
remote, authenticated user could use this flaw to bypass intended
SecurityManager restrictions and list a parent directory via a '/..'
in a pathname used by a web application in a getResource,
getResourceAsStream, or getResourcePaths call. (CVE-2015-5174)

* It was found that Tomcat could reveal the presence of a directory
even when that directory was protected by a security constraint. A
user could make a request to a directory via a URL not ending with a
slash and, depending on whether Tomcat redirected that request, could
confirm whether that directory existed. (CVE-2015-5345)

* It was found that Tomcat allowed the StatusManagerServlet to be
loaded by a web application when a security manager was configured.
This allowed a web application to list all deployed web applications
and expose sensitive information such as session IDs. (CVE-2016-0706)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-November/006483.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-el-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-jsp-2.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-servlet-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-7.0.69-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-admin-webapps-7.0.69-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-docs-webapp-7.0.69-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-el-2.2-api-7.0.69-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-javadoc-7.0.69-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-jsp-2.2-api-7.0.69-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-jsvc-7.0.69-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-lib-7.0.69-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-servlet-3.0-api-7.0.69-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tomcat-webapps-7.0.69-10.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}

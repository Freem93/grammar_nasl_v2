#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0865 and 
# Oracle Linux Security Advisory ELSA-2014-0865 respectively.
#

include("compat.inc");

if (description)
{
  script_id(76442);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:25:14 $");

  script_cve_id("CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099");
  script_bugtraq_id(65400, 65767, 67667, 67668, 67671);
  script_osvdb_id(107450, 107452, 107475);
  script_xref(name:"RHSA", value:"2014:0865");

  script_name(english:"Oracle Linux 6 : tomcat6 (ELSA-2014-0865)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0865 :

Updated tomcat6 packages that fix three security issues and two bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

It was discovered that Apache Tomcat did not limit the length of chunk
sizes when using chunked transfer encoding. A remote attacker could
use this flaw to perform a denial of service attack against Tomcat by
streaming an unlimited quantity of data, leading to excessive
consumption of server resources. (CVE-2014-0075)

It was found that Apache Tomcat did not check for overflowing values
when parsing request content length headers. A remote attacker could
use this flaw to perform an HTTP request smuggling attack on a Tomcat
server located behind a reverse proxy that processed the content
length header correctly. (CVE-2014-0099)

It was found that the org.apache.catalina.servlets.DefaultServlet
implementation in Apache Tomcat allowed the definition of XML External
Entities (XXEs) in provided XSLTs. A malicious application could use
this to circumvent intended security restrictions to disclose
sensitive information. (CVE-2014-0096)

The CVE-2014-0075 issue was discovered by David Jorm of Red Hat
Product Security.

This update also fixes the following bugs :

* The patch that resolved the CVE-2014-0050 issue contained redundant
code. This update removes the redundant code. (BZ#1094528)

* The patch that resolved the CVE-2013-4322 issue contained an invalid
check that triggered a java.io.EOFException while reading trailer
headers for chunked requests. This update fixes the check and the
aforementioned exception is no longer triggered in the described
scenario. (BZ#1095602)

All Tomcat 6 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. Tomcat must
be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-July/004220.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"tomcat6-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-admin-webapps-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-docs-webapp-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-el-2.1-api-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-javadoc-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-jsp-2.1-api-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-lib-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-servlet-2.5-api-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-webapps-6.0.24-72.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6 / tomcat6-admin-webapps / tomcat6-docs-webapp / etc");
}

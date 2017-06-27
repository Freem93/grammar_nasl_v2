#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(76450);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/06 14:51:23 $");

  script_cve_id("CVE-2013-4322", "CVE-2014-0050", "CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099");

  script_name(english:"Scientific Linux Security Update : tomcat6 on SL6.x i386/srpm/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Apache Tomcat did not limit the length of chunk
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

This update also fixes the following bugs :

  - The patch that resolved the CVE-2014-0050 issue
    contained redundant code. This update removes the
    redundant code.

  - The patch that resolved the CVE-2013-4322 issue
    contained an invalid check that triggered a
    java.io.EOFException while reading trailer headers for
    chunked requests. This update fixes the check and the
    aforementioned exception is no longer triggered in the
    described scenario.

Tomcat must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1407&L=scientific-linux-errata&T=0&P=424
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?463d203c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"tomcat6-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-admin-webapps-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-admin-webapps-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-docs-webapp-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-docs-webapp-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-el-2.1-api-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-el-2.1-api-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-javadoc-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-javadoc-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-jsp-2.1-api-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-jsp-2.1-api-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-lib-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-lib-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-servlet-2.5-api-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-servlet-2.5-api-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-webapps-6.0.24-72.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-webapps-6.0.24-72.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61299);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/13 15:30:40 $");

  script_cve_id("CVE-2011-4858", "CVE-2012-0022");

  script_name(english:"Scientific Linux Security Update : tomcat5 on SL5.x i386/x86_64");
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
"Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

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

Users of Tomcat should upgrade to these updated packages, which
correct these issues. Tomcat must be restarted for this update to take
effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1204&L=scientific-linux-errata&T=0&P=1225
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbecc1a7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"tomcat5-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-admin-webapps-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-common-lib-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-debuginfo-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jasper-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-server-lib-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.31.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-webapps-5.5.23-0jpp.31.el5_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

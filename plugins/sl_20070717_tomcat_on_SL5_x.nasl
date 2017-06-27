#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60227);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2005-2090", "CVE-2006-7195", "CVE-2007-0450", "CVE-2007-2449", "CVE-2007-2450");

  script_name(english:"Scientific Linux Security Update : tomcat on SL5.x i386/x86_64");
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
"Some JSPs within the 'examples' web application did not escape user
provided data. If the JSP examples were accessible, this flaw could
allow a remote attacker to perform cross-site scripting attacks
(CVE-2007-2449).

Note: it is recommended the 'examples' web application not be
installed on a production system.

The Manager and Host Manager web applications did not escape user
provided data. If a user is logged in to the Manager or Host Manager
web application, an attacker could perform a cross-site scripting
attack (CVE-2007-2450).

Tomcat was found to accept multiple content-length headers in a
request. This could allow attackers to poison a web-cache, bypass web
application firewall protection, or conduct cross-site scripting
attacks. (CVE-2005-2090)

Tomcat permitted various characters as path delimiters. If Tomcat was
used behind certain proxies and configured to only proxy some
contexts, an attacker could construct an HTTP request to work around
the context restriction and potentially access non-proxied content.
(CVE-2007-0450)

The implict-objects.jsp file distributed in the examples webapp
displayed a number of unfiltered header values. If the JSP examples
were accessible, this flaw could allow a remote attacker to perform
cross-site scripting attacks. (CVE-2006-7195)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0709&L=scientific-linux-errata&T=0&P=1147
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d35b9ec"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"jakarta-commons-modeler-1.1-8jpp.1.0.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"jakarta-commons-modeler-javadoc-1.1-8jpp.1.0.2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-5.5.23-0jpp.1.0.4")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-admin-webapps-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-admin-webapps-5.5.23-0jpp.1.0.4")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-common-lib-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-common-lib-5.5.23-0jpp.1.0.4")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-jasper-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-jasper-5.5.23-0jpp.1.0.4")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.1.0.4")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.1.0.4")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.1.0.4")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-server-lib-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-server-lib-5.5.23-0jpp.1.0.4")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.1.0.4")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.1.0.4")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"tomcat5-webapps-5.5.23-0jpp.1.0.4.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"tomcat5-webapps-5.5.23-0jpp.1.0.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

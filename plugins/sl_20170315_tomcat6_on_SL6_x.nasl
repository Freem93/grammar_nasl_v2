#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(97770);
  script_version("$Revision: 3.6 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id("CVE-2016-6816", "CVE-2016-8745");

  script_name(english:"Scientific Linux Security Update : tomcat6 on SL6.x (noarch)");
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
"Security Fix(es) :

  - It was discovered that the code that parsed the HTTP
    request line permitted invalid characters. This could be
    exploited, in conjunction with a proxy that also
    permitted the invalid characters but with a different
    interpretation, to inject data into the HTTP response.
    By manipulating the HTTP response the attacker could
    poison a web-cache, perform an XSS attack, or obtain
    sensitive information from requests other then their
    own. (CVE-2016-6816)

Note: This fix causes Tomcat to respond with an HTTP 400 Bad Request
error when request contains characters that are not permitted by the
HTTP specification to appear not encoded, even though they were
previously accepted. The newly introduced system property
tomcat.util.http.parser.HttpParser.requestTargetAllow can be used to
configure Tomcat to accept curly braces ({ and }) and the pipe symbol
(|) in not encoded form, as these are often used in URLs without being
properly encoded.

  - A bug was discovered in the error handling of the send
    file code for the NIO HTTP connector. This led to the
    current Processor object being added to the Processor
    cache multiple times allowing information leakage
    between requests including, and not limited to, session
    ID and the response body. (CVE-2016-8745)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1703&L=scientific-linux-errata&F=&S=&P=8501
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c870ec1f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"tomcat6-6.0.24-105.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-admin-webapps-6.0.24-105.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-docs-webapp-6.0.24-105.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-el-2.1-api-6.0.24-105.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-javadoc-6.0.24-105.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-jsp-2.1-api-6.0.24-105.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-lib-6.0.24-105.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-servlet-2.5-api-6.0.24-105.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-webapps-6.0.24-105.el6_8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

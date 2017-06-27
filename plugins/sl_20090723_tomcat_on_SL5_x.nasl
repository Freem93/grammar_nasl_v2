#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60621);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2007-5333", "CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783");

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
"It was discovered that a prior security errata for Tomcat version
tomcat5-5.5.23-0jpp.3.0.2.el5 did not address all possible flaws in
the way Tomcat handles certain characters and character sequences in
cookie values. A remote attacker could use this flaw to obtain
sensitive information, such as session IDs, and then use this
information for session hijacking attacks. (CVE-2007-5333)

Note: The fix for the CVE-2007-5333 flaw changes the default cookie
processing behavior: with this update, version 0 cookies that contain
values that must be quoted to be valid are automatically changed to
version 1 cookies. To reactivate the previous, but insecure behavior,
add the following entry to the '/etc/tomcat5/catalina.properties' 
file :

org.apache.tomcat.util.http.ServerCookie.VERSION_SWITCH=false

It was discovered that request dispatchers did not properly normalize
user requests that have trailing query strings, allowing remote
attackers to send specially crafted requests that would cause an
information leak. (CVE-2008-5515)

A flaw was found in the way the Tomcat AJP (Apache JServ Protocol)
connector processes AJP connections. An attacker could use this flaw
to send specially crafted requests that would cause a temporary denial
of service. (CVE-2009-0033)

It was discovered that the error checking methods of certain
authentication classes did not have sufficient error checking,
allowing remote attackers to enumerate (via brute-force methods)
usernames registered with applications running on Tomcat when
FORM-based authentication was used. (CVE-2009-0580)

A cross-site scripting (XSS) flaw was found in the examples calendar
application. With some web browsers, remote attackers could use this
flaw to inject arbitrary web script or HTML via the 'time' parameter.
(CVE-2009-0781)

It was discovered that web applications containing their own XML
parsers could replace the XML parser Tomcat uses to parse
configuration files. A malicious web application running on a Tomcat
instance could read or, potentially, modify the configuration and
XML-based data of other web applications deployed on the same Tomcat
instance. (CVE-2009-0783)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0907&L=scientific-linux-errata&T=0&P=1780
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6256e92"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 22, 79, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

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
if (rpm_check(release:"SL5", reference:"tomcat5-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-admin-webapps-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-common-lib-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jasper-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-server-lib-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.7.el5_3.2")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-webapps-5.5.23-0jpp.7.el5_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(77144);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/12 14:41:11 $");

  script_cve_id("CVE-2013-4590", "CVE-2014-0119");

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
"It was found that several application-provided XML files, such as
web.xml, content.xml, *.tld, *.tagx, and *.jspx, resolved external
entities, permitting XML External Entity (XXE) attacks. An attacker
able to deploy malicious applications to Tomcat could use this flaw to
circumvent security restrictions set by the JSM, and gain access to
sensitive information on the system. Note that this flaw only affected
deployments in which Tomcat is running applications from untrusted
sources, such as in a shared hosting environment. (CVE-2013-4590)

It was found that, in certain circumstances, it was possible for a
malicious web application to replace the XML parsers used by Apache
Tomcat to process XSLTs for the default servlet, JSP documents, tag
library descriptors (TLDs), and tag plug-in configuration files. The
injected XML parser(s) could then bypass the limits imposed on XML
external entities and/or gain access to the XML files processed for
other web applications deployed on the same Apache Tomcat instance.
(CVE-2014-0119)

Tomcat must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1408&L=scientific-linux-errata&T=0&P=709
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e47c8c3a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"tomcat6-6.0.24-78.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-admin-webapps-6.0.24-78.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-docs-webapp-6.0.24-78.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-el-2.1-api-6.0.24-78.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-javadoc-6.0.24-78.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-jsp-2.1-api-6.0.24-78.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-lib-6.0.24-78.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-servlet-2.5-api-6.0.24-78.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-webapps-6.0.24-78.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

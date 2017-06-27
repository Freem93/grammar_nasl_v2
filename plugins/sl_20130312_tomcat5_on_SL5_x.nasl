#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65244);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/18 02:53:55 $");

  script_cve_id("CVE-2012-3546", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887");

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
"It was found that when an application used FORM authentication, along
with another component that calls request.setUserPrincipal() before
the call to FormAuthenticator#authenticate() (such as the
Single-Sign-On valve), it was possible to bypass the security
constraint checks in the FORM authenticator by appending
'/j_security_check' to the end of a URL. A remote attacker with an
authenticated session on an affected application could use this flaw
to circumvent authorization controls, and thereby access resources not
permitted by the roles associated with their authenticated session.
(CVE-2012-3546)

Multiple weaknesses were found in the Tomcat DIGEST authentication
implementation, effectively reducing the security normally provided by
DIGEST authentication. A remote attacker could use these flaws to
perform replay attacks in some circumstances. (CVE-2012-5885,
CVE-2012-5886, CVE-2012-5887)

Tomcat must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=4258
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dcb6468c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"tomcat5-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-admin-webapps-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-common-lib-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-debuginfo-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jasper-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-server-lib-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.38.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"tomcat5-webapps-5.5.23-0jpp.38.el5_9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

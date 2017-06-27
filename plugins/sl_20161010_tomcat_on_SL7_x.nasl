#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(94005);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/11/04 15:55:10 $");

  script_cve_id("CVE-2014-7810", "CVE-2015-5346", "CVE-2016-5388", "CVE-2016-5425", "CVE-2016-6325");

  script_name(english:"Scientific Linux Security Update : tomcat on SL7.x (noarch) (httpoxy)");
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

  - It was discovered that the Tomcat packages installed
    configuration file /usr/lib/tmpfiles.d/tomcat.conf
    writeable to the tomcat group. A member of the group or
    a malicious web application deployed on Tomcat could use
    this flaw to escalate their privileges. (CVE-2016-5425)

  - It was discovered that the Tomcat packages installed
    certain configuration files read by the Tomcat
    initialization script as writeable to the tomcat group.
    A member of the group or a malicious web application
    deployed on Tomcat could use this flaw to escalate their
    privileges. (CVE-2016-6325)

  - It was found that the expression language resolver
    evaluated expressions within a privileged code section.
    A malicious web application could use this flaw to
    bypass security manager protections. (CVE-2014-7810)

  - It was discovered that tomcat used the value of the
    Proxy header from HTTP requests to initialize the
    HTTP_PROXY environment variable for CGI scripts, which
    in turn was incorrectly used by certain HTTP client
    implementations to configure the proxy for outgoing HTTP
    requests. A remote attacker could possibly use this flaw
    to redirect HTTP requests performed by a CGI script to
    an attacker-controlled proxy via a malicious HTTP
    request. (CVE-2016-5388)

  - A session fixation flaw was found in the way Tomcat
    recycled the requestedSessionSSL field. If at least one
    web application was configured to use the SSL session ID
    as the HTTP session ID, an attacker could reuse a
    previously used session ID for further requests.
    (CVE-2015-5346)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1610&L=scientific-linux-errata&F=&S=&P=1735
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a841931"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/10");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", reference:"tomcat-7.0.54-8.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-admin-webapps-7.0.54-8.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-docs-webapp-7.0.54-8.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-el-2.2-api-7.0.54-8.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-javadoc-7.0.54-8.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-jsp-2.2-api-7.0.54-8.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-jsvc-7.0.54-8.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-lib-7.0.54-8.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-servlet-3.0-api-7.0.54-8.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"tomcat-webapps-7.0.54-8.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

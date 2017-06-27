#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(83455);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/05/24 04:37:34 $");

  script_cve_id("CVE-2014-0227");

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
"It was discovered that the ChunkedInputFilter in Tomcat did not fail
subsequent attempts to read input after malformed chunked encoding was
detected. A remote attacker could possibly use this flaw to make
Tomcat process part of the request body as new request, or cause a
denial of service. (CVE-2014-0227)

This update also fixes the following bug :

  - Before this update, the tomcat6 init script did not try
    to kill the tomcat process if an attempt to stop it was
    unsuccessful, which would prevent tomcat from restarting
    properly. The init script was modified to correct this
    issue.

Tomcat must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1505&L=scientific-linux-errata&T=0&P=1865
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41da8f8e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"tomcat6-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-admin-webapps-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-debuginfo-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-debuginfo-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-docs-webapp-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-el-2.1-api-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-javadoc-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-jsp-2.1-api-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-lib-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-servlet-2.5-api-6.0.24-83.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"tomcat6-webapps-6.0.24-83.el6_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

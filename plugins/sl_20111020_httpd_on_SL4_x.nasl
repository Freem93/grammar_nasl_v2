#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61160);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/13 15:30:40 $");

  script_cve_id("CVE-2011-3368");

  script_name(english:"Scientific Linux Security Update : httpd on SL4.x, SL5.x i386/x86_64");
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
"The Apache HTTP Server is a popular web server.

It was discovered that the Apache HTTP Server did not properly
validate the request URI for proxied requests. In certain
configurations, if a reverse proxy used the ProxyPassMatch directive,
or if it used the RewriteRule directive with the proxy flag, a remote
attacker could make the proxy connect to an arbitrary server, possibly
disclosing sensitive information from internal web servers not
directly accessible to the attacker. (CVE-2011-3368)

This update also fixes the following bug :

  - The fix for CVE-2011-3192 provided by a previous update
    introduced regressions in the way httpd handled certain
    Range HTTP header values. This update corrects those
    regressions.

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1110&L=scientific-linux-errata&T=0&P=2404
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?104a6834"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/20");
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
if (rpm_check(release:"SL4", reference:"httpd-2.0.52-49.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-debuginfo-2.0.52-49.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-devel-2.0.52-49.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-manual-2.0.52-49.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-suexec-2.0.52-49.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"mod_ssl-2.0.52-49.sl4")) flag++;

if (rpm_check(release:"SL5", reference:"httpd-2.2.3-53.sl5.3")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-debuginfo-2.2.3-53.sl5.3")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-devel-2.2.3-53.sl5.3")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-53.sl5.3")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-53.sl5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

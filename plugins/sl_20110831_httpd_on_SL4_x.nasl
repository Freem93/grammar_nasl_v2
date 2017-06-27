#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61126);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/13 15:30:40 $");

  script_cve_id("CVE-2011-3192");

  script_name(english:"Scientific Linux Security Update : httpd on SL4.x, SL5.x, SL6.x i386/x86_64");
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

A flaw was found in the way the Apache HTTP Server handled Range HTTP
headers. A remote attacker could use this flaw to cause httpd to use
an excessive amount of memory and CPU time via HTTP requests with a
specially crafted Range header. (CVE-2011-3192)

All httpd users should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1109&L=scientific-linux-errata&T=0&P=80
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?508a687e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/31");
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
if (rpm_check(release:"SL4", reference:"httpd-2.0.52-48.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-devel-2.0.52-48.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-manual-2.0.52-48.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"httpd-suexec-2.0.52-48.sl4")) flag++;
if (rpm_check(release:"SL4", reference:"mod_ssl-2.0.52-48.sl4")) flag++;

if (rpm_check(release:"SL5", reference:"httpd-2.2.3-53.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-devel-2.2.3-53.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"httpd-manual-2.2.3-53.sl5.1")) flag++;
if (rpm_check(release:"SL5", reference:"mod_ssl-2.2.3-53.sl5.1")) flag++;

if (rpm_check(release:"SL6", reference:"httpd-2.2.15-9.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-devel-2.2.15-9.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-manual-2.2.15-9.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-tools-2.2.15-9.sl6.2")) flag++;
if (rpm_check(release:"SL6", reference:"mod_ssl-2.2.15-9.sl6.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

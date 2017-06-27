#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61036);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/07/20 01:56:57 $");

  script_cve_id("CVE-2011-0419");

  script_name(english:"Scientific Linux Security Update : apr on SL4.x, SL5.x, SL6.x i386/x86_64");
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
"It was discovered that the apr_fnmatch() function used an
unconstrained recursion when processing patterns with the '*'
wildcard. An attacker could use this flaw to cause an application
using this function, which also accepted untrusted input as a pattern
for matching (such as an httpd server using the mod_autoindex module),
to exhaust all stack memory or use an excessive amount of CPU time
when performing matching. (CVE-2011-0419)

Applications using the apr library, such as httpd, must be restarted
for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1105&L=scientific-linux-errata&T=0&P=1112
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?582e44f6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apr, apr-devel and / or apr-docs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"apr-0.9.4-25.el4")) flag++;
if (rpm_check(release:"SL4", reference:"apr-devel-0.9.4-25.el4")) flag++;

if (rpm_check(release:"SL5", reference:"apr-1.2.7-11.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"apr-devel-1.2.7-11.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"apr-docs-1.2.7-11.el5_6.4")) flag++;

if (rpm_check(release:"SL6", reference:"apr-1.3.9-3.el6_0.1")) flag++;
if (rpm_check(release:"SL6", reference:"apr-devel-1.3.9-3.el6_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

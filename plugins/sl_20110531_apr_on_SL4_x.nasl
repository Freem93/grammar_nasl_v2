#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61052);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/15 16:37:17 $");

  script_cve_id("CVE-2011-1928");

  script_name(english:"Scientific Linux Security Update : apr on SL4.x, SL5.x i386/x86_64");
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
"The Apache Portable Runtime (APR) is a portability library used by the
Apache HTTP Server and other projects. It provides a free library of C
data structures and routines.

The fix for CVE-2011-0419 introduced an infinite loop flaw in the
apr_fnmatch() function when the APR_FNM_PATHNAME matching flag was
used. A remote attacker could possibly use this flaw to cause a denial
of service on an application using the apr_fnmatch() function.
(CVE-2011-1928)

Note: This problem affected httpd configurations using the 'Location'
directive with wildcard URLs. The denial of service could have been
triggered during normal operation; it did not specifically require a
malicious HTTP request.

This update also addresses additional problems introduced by the
rewrite of the apr_fnmatch() function, which was necessary to address
the CVE-2011-0419 flaw.

All apr users should upgrade to these updated packages, which contain
a backported patch to correct this issue. Applications using the apr
library, such as httpd, must be restarted for this update to take
effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=1394
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf8f36c5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
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
if (rpm_check(release:"SL4", reference:"apr-0.9.4-26.el4")) flag++;
if (rpm_check(release:"SL4", reference:"apr-debuginfo-0.9.4-26.el4")) flag++;
if (rpm_check(release:"SL4", reference:"apr-devel-0.9.4-26.el4")) flag++;

if (rpm_check(release:"SL5", reference:"apr-1.2.7-11.el5_6.5")) flag++;
if (rpm_check(release:"SL5", reference:"apr-debuginfo-1.2.7-11.el5_6.5")) flag++;
if (rpm_check(release:"SL5", reference:"apr-devel-1.2.7-11.el5_6.5")) flag++;
if (rpm_check(release:"SL5", reference:"apr-docs-1.2.7-11.el5_6.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

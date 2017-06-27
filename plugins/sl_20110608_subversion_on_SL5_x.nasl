#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61067);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-1752", "CVE-2011-1783", "CVE-2011-1921");

  script_name(english:"Scientific Linux Security Update : subversion on SL5.x, SL6.x i386/x86_64");
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
"Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

An infinite loop flaw was found in the way the mod_dav_svn module
processed certain data sets. If the SVNPathAuthz directive was set to
'short_circuit', and path-based access control for files and
directories was enabled, a malicious, remote user could use this flaw
to cause the httpd process serving the request to consume an excessive
amount of system memory. (CVE-2011-1783)

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module processed requests submitted against the URL of a baselined
resource. A malicious, remote user could use this flaw to cause the
httpd process serving the request to crash. (CVE-2011-1752)

An information disclosure flaw was found in the way the mod_dav_svn
module processed certain URLs when path-based access control for files
and directories was enabled. A malicious, remote user could possibly
use this flaw to access certain files in a repository that would
otherwise not be accessible to them. Note: This vulnerability cannot
be triggered if the SVNPathAuthz directive is set to 'short_circuit'.
(CVE-2011-1921)

All Subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, you must restart the httpd daemon, if you are
using mod_dav_svn, for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=3110
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae903495"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"mod_dav_svn-1.6.11-7.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-1.6.11-7.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-debuginfo-1.6.11-7.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-devel-1.6.11-7.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-javahl-1.6.11-7.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-perl-1.6.11-7.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-ruby-1.6.11-7.el5_6.4")) flag++;

if (rpm_check(release:"SL6", reference:"mod_dav_svn-1.6.11-2.el6_1.4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-1.6.11-2.el6_1.4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-debuginfo-1.6.11-2.el6_1.4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-devel-1.6.11-2.el6_1.4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-gnome-1.6.11-2.el6_1.4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-javahl-1.6.11-2.el6_1.4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-kde-1.6.11-2.el6_1.4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-perl-1.6.11-2.el6_1.4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-ruby-1.6.11-2.el6_1.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

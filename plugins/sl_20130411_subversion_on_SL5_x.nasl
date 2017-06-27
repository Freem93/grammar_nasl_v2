#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65957);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/04 23:38:20 $");

  script_cve_id("CVE-2013-1845", "CVE-2013-1846", "CVE-2013-1847", "CVE-2013-1849");

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
"A NULL pointer dereference flaw was found in the way the mod_dav_svn
module handled PROPFIND requests on activity URLs. A remote attacker
could use this flaw to cause the httpd process serving the request to
crash. (CVE-2013-1849)

A flaw was found in the way the mod_dav_svn module handled large
numbers of properties (such as those set with the 'svn propset'
command). A malicious, remote user could use this flaw to cause the
httpd process serving the request to consume an excessive amount of
system memory. (CVE-2013-1845)

Two NULL pointer dereference flaws were found in the way the
mod_dav_svn module handled LOCK requests on certain types of URLs. A
malicious, remote user could use these flaws to cause the httpd
process serving the request to crash. (CVE-2013-1846, CVE-2013-1847)

Note: The CVE-2013-1849, CVE-2013-1846, and CVE-2013-1847 issues only
caused a temporary denial of service, as the Apache HTTP Server
started a new process to replace the crashed child process. When using
prefork MPM, the crash only affected the attacker. When using worker
(threaded) MPM, the connections of other users may have been
interrupted.

After installing the updated packages, you must restart the httpd
daemon, if you are using mod_dav_svn, for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1304&L=scientific-linux-errata&T=0&P=818
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07f13a89"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/13");
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
if (rpm_check(release:"SL5", reference:"mod_dav_svn-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-debuginfo-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-devel-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-javahl-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-perl-1.6.11-11.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-ruby-1.6.11-11.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"mod_dav_svn-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-debuginfo-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-devel-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-gnome-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-javahl-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-kde-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-perl-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-ruby-1.6.11-9.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-svn2cl-1.6.11-9.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

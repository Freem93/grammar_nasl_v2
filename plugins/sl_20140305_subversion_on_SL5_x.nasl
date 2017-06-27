#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(72855);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/03/06 11:47:45 $");

  script_cve_id("CVE-2013-1968", "CVE-2013-2112", "CVE-2014-0032");

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
"A flaw was found in the way the mod_dav_svn module handled OPTIONS
requests. A remote attacker with read access to an SVN repository
served via HTTP could use this flaw to cause the httpd process that
handled such a request to crash. (CVE-2014-0032)

A flaw was found in the way Subversion handled file names with newline
characters when the FSFS repository format was used. An attacker with
commit access to an SVN repository could corrupt a revision by
committing a specially crafted file. (CVE-2013-1968)

A flaw was found in the way the svnserve tool of Subversion handled
remote client network connections. An attacker with read access to an
SVN repository served via svnserve could use this flaw to cause the
svnserve daemon to exit, leading to a denial of service.
(CVE-2013-2112)

After installing the updated packages, for the update to take effect,
you must restart the httpd daemon, if you are using mod_dav_svn, and
the svnserve daemon, if you are serving Subversion repositories via
the svn:// protocol."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1403&L=scientific-linux-errata&T=0&P=451
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5865ce07"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/06");
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
if (rpm_check(release:"SL5", reference:"mod_dav_svn-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-debuginfo-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-devel-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-javahl-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-perl-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-ruby-1.6.11-12.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"mod_dav_svn-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-debuginfo-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-devel-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-gnome-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-javahl-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-kde-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-perl-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-ruby-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"subversion-svn2cl-1.6.11-10.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

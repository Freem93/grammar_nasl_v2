#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85867);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/09 14:39:26 $");

  script_cve_id("CVE-2015-0248", "CVE-2015-0251", "CVE-2015-3184", "CVE-2015-3187");

  script_name(english:"Scientific Linux Security Update : subversion on SL7.x x86_64");
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
"An assertion failure flaw was found in the way the SVN server
processed certain requests with dynamically evaluated revision
numbers. A remote attacker could use this flaw to cause the SVN server
(both svnserve and httpd with the mod_dav_svn module) to crash.
(CVE-2015-0248)

It was found that the mod_authz_svn module did not properly restrict
anonymous access to Subversion repositories under certain
configurations when used with Apache httpd 2.4.x. This could allow a
user to anonymously access files in a Subversion repository, which
should only be accessible to authenticated users. (CVE-2015-3184)

It was found that the mod_dav_svn module did not properly validate the
svn:author property of certain requests. An attacker able to create
new revisions could use this flaw to spoof the svn:author property.
(CVE-2015-0251)

It was found that when an SVN server (both svnserve and httpd with the
mod_dav_svn module) searched the history of a file or a directory, it
would disclose its location in the repository if that file or
directory was not readable (for example, if it had been moved).
(CVE-2015-3187)

After installing the updated packages, for the update to take effect,
you must restart the httpd daemon, if you are using mod_dav_svn, and
the svnserve daemon, if you are serving Subversion repositories via
the svn:// protocol."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1509&L=scientific-linux-errata&F=&S=&P=10618
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3be87462"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_dav_svn-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-debuginfo-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-devel-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-gnome-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-javahl-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-kde-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-libs-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-perl-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-python-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-ruby-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"subversion-tools-1.7.14-7.el7_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

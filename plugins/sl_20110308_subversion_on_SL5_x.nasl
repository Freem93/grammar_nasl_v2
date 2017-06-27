#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60982);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2011-0715");

  script_name(english:"Scientific Linux Security Update : subversion on SL5.x i386/x86_64");
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
module processed certain requests to lock working copy paths in a
repository. A remote attacker could issue a lock request that could
cause the httpd process serving the request to crash. (CVE-2011-0715)

This update also fixes the following bug :

  - A regression was found in the handling of repositories
    which do not have a 'db/fsfs.conf' file. The 'svnadmin
    hotcopy' command would fail when trying to produce a
    copy of such a repository. This command has been fixed
    to ignore the absence of the 'fsfs.conf' file. The
    'svnadmin hotcopy' command will now succeed for this
    type of repository. (BZ#681522)

After installing the updated packages, you must restart the httpd
daemon, if you are using mod_dav_svn, for the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1103&L=scientific-linux-errata&T=0&P=7883
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e961a7b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=681522"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/08");
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
if (rpm_check(release:"SL5", reference:"mod_dav_svn-1.6.11-7.el5_6.3")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-1.6.11-7.el5_6.3")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-devel-1.6.11-7.el5_6.3")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-javahl-1.6.11-7.el5_6.3")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-perl-1.6.11-7.el5_6.3")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-ruby-1.6.11-7.el5_6.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

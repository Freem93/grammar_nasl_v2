#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60954);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:55 $");

  script_cve_id("CVE-2010-4539", "CVE-2010-4644");

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
"A server-side memory leak was found in the Subversion server. If a
malicious, remote user performed 'svn blame' or 'svn log' operations
on certain repository files, it could cause the Subversion server to
consume a large amount of system memory. (CVE-2010-4644)

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module (for use with the Apache HTTP Server) processed certain
requests. If a malicious, remote user issued a certain type of request
to display a collection of Subversion repositories on a host that has
the SVNListParentPath directive enabled, it could cause the httpd
process serving the request to crash. Note that SVNListParentPath is
not enabled by default. (CVE-2010-4539)

After installing the updated packages, the Subversion server must be
restarted for the update to take effect: restart httpd if you are
using mod_dav_svn, or restart svnserve if it is used."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1102&L=scientific-linux-errata&T=0&P=1243
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6befcb6b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/15");
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
if (rpm_check(release:"SL5", reference:"mod_dav_svn-1.6.11-7.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-1.6.11-7.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-devel-1.6.11-7.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-javahl-1.6.11-7.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-perl-1.6.11-7.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-ruby-1.6.11-7.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

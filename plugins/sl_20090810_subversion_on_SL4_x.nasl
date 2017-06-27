#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60638);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2009-2411");

  script_name(english:"Scientific Linux Security Update : subversion on SL4.x, SL5.x i386/x86_64");
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
"CVE-2009-2411 subversion: multiple heap overflow issues

Matt Lewis, of Google, reported multiple heap overflow flaws in
Subversion (server and client) when parsing binary deltas. A malicious
user with commit access to a server could use these flaws to cause a
heap overflow on that server. A malicious server could use these flaws
to cause a heap overflow on a client when it attempts to checkout or
update. These heap overflows can result in a crash or, possibly,
arbitrary code execution. (CVE-2009-2411)

After installing the updated packages, the Subversion server must be
restarted for the update to take effect: restart httpd if you are
using mod_dav_svn, or restart svnserve if it is used."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0908&L=scientific-linux-errata&T=0&P=847
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?783979f1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/10");
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
if (rpm_check(release:"SL4", reference:"mod_dav_svn-1.1.4-3.el4_8.2")) flag++;
if (rpm_check(release:"SL4", reference:"subversion-1.1.4-3.el4_8.2")) flag++;
if (rpm_check(release:"SL4", reference:"subversion-devel-1.1.4-3.el4_8.2")) flag++;
if (rpm_check(release:"SL4", reference:"subversion-perl-1.1.4-3.el4_8.2")) flag++;

if (rpm_check(release:"SL5", reference:"mod_dav_svn-1.4.2-4.el5_3.1")) flag++;
if (rpm_check(release:"SL5", reference:"neon-0.25.5-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"neon-devel-0.25.5-10.el5")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-1.4.2-4.el5_3.1")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-devel-1.4.2-4.el5_3.1")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-javahl-1.4.2-4.el5_3.1")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-perl-1.4.2-4.el5_3.1")) flag++;
if (rpm_check(release:"SL5", reference:"subversion-ruby-1.4.2-4.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

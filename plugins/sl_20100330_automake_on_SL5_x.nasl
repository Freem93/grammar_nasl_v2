#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60761);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/03 00:00:32 $");

  script_cve_id("CVE-2009-4029");

  script_name(english:"Scientific Linux Security Update : automake on SL5.x i386/x86_64");
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
"Automake-generated Makefiles made certain directories world-writable
when preparing source archives, as was recommended by the GNU Coding
Standards. If a malicious, local user could access the directory where
a victim was creating distribution archives, they could use this flaw
to modify the files being added to those archives. Makefiles generated
by these updated automake packages no longer make distribution
directories world-writable, as recommended by the updated GNU Coding
Standards. (CVE-2009-4029)

Note: This issue affected Makefile targets used by developers to
prepare distribution source archives. Those targets are not used when
compiling programs from the source code."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1004&L=scientific-linux-errata&T=0&P=2162
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?428be9b8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
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
if (rpm_check(release:"SL5", reference:"automake-1.9.6-2.3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"automake14-1.4p6-13.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"automake15-1.5-16.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"automake16-1.6.3-8.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"automake17-1.7.9-7.el5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60806);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-0540", "CVE-2010-0542", "CVE-2010-1748");

  script_name(english:"Scientific Linux Security Update : cups on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"A missing memory allocation failure check flaw, leading to a NULL
pointer dereference, was found in the CUPS 'texttops' filter. An
attacker could create a malicious text file that would cause
'texttops' to crash or, potentially, execute arbitrary code as the
'lp' user if the file was printed. (CVE-2010-0542)

A Cross-Site Request Forgery (CSRF) issue was found in the CUPS web
interface. If a remote attacker could trick a user, who is logged into
the CUPS web interface as an administrator, into visiting a specially
crafted website, the attacker could reconfigure and disable CUPS, and
gain access to print jobs and system files. (CVE-2010-0540)

Note: As a result of the fix for CVE-2010-0540, cookies must now be
enabled in your web browser to use the CUPS web interface.

An uninitialized memory read issue was found in the CUPS web
interface. If an attacker had access to the CUPS web interface, they
could use a specially crafted URL to leverage this flaw to read a
limited amount of memory from the cupsd process, possibly obtaining
sensitive information. (CVE-2010-1748)

After installing this update, the cupsd daemon will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1006&L=scientific-linux-errata&T=0&P=1894
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5b9d69c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"cups-1.1.17-13.3.65")) flag++;
if (rpm_check(release:"SL3", reference:"cups-devel-1.1.17-13.3.65")) flag++;
if (rpm_check(release:"SL3", reference:"cups-libs-1.1.17-13.3.65")) flag++;

if (rpm_check(release:"SL4", reference:"cups-1.1.22-0.rc1.9.32.el4_8.6")) flag++;
if (rpm_check(release:"SL4", reference:"cups-devel-1.1.22-0.rc1.9.32.el4_8.6")) flag++;
if (rpm_check(release:"SL4", reference:"cups-libs-1.1.22-0.rc1.9.32.el4_8.6")) flag++;

if (rpm_check(release:"SL5", reference:"cups-1.3.7-18.el5_5.4")) flag++;
if (rpm_check(release:"SL5", reference:"cups-devel-1.3.7-18.el5_5.4")) flag++;
if (rpm_check(release:"SL5", reference:"cups-libs-1.3.7-18.el5_5.4")) flag++;
if (rpm_check(release:"SL5", reference:"cups-lpd-1.3.7-18.el5_5.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

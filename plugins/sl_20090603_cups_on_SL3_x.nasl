#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60592);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-0791", "CVE-2009-0949", "CVE-2009-1196");

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
"A NULL pointer dereference flaw was found in the CUPS IPP routine,
used for processing incoming IPP requests for the CUPS scheduler. An
attacker could use this flaw to send specially crafted IPP requests
that would crash the cupsd daemon. (CVE-2009-0949)

A use-after-free flaw was found in the CUPS scheduler directory
services routine, used to process data about available printers and
printer classes. An attacker could use this flaw to cause a denial of
service (cupsd daemon stop or crash). (CVE-2009-1196)

Multiple integer overflows flaws, leading to heap-based buffer
overflows, were found in the CUPS 'pdftops' filter. An attacker could
create a malicious PDF file that would cause 'pdftops' to crash or,
potentially, execute arbitrary code as the 'lp' user if the file was
printed. (CVE-2009-0791)

After installing this update, the cupsd daemon will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0906&L=scientific-linux-errata&T=0&P=75
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f50ada89"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"cups-1.1.17-13.3.62")) flag++;
if (rpm_check(release:"SL3", reference:"cups-devel-1.1.17-13.3.62")) flag++;
if (rpm_check(release:"SL3", reference:"cups-libs-1.1.17-13.3.62")) flag++;

if (rpm_check(release:"SL4", reference:"cups-1.1.22-0.rc1.9.32.el4_8.3")) flag++;
if (rpm_check(release:"SL4", reference:"cups-devel-1.1.22-0.rc1.9.32.el4_8.3")) flag++;
if (rpm_check(release:"SL4", reference:"cups-libs-1.1.22-0.rc1.9.32.el4_8.3")) flag++;

if (rpm_check(release:"SL5", reference:"cups-1.3.7-8.el5_3.6")) flag++;
if (rpm_check(release:"SL5", reference:"cups-devel-1.3.7-8.el5_3.6")) flag++;
if (rpm_check(release:"SL5", reference:"cups-libs-1.3.7-8.el5_3.6")) flag++;
if (rpm_check(release:"SL5", reference:"cups-lpd-1.3.7-8.el5_3.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

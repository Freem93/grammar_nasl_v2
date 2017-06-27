#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60294);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2007-4033", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");

  script_name(english:"Scientific Linux Security Update : tetex on SL5.x, SL4.x, SL3.x i386/x86_64");
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
"Alin Rad Pop discovered several flaws in the handling of PDF files. An
attacker could create a malicious PDF file that would cause TeTeX to
crash or potentially execute arbitrary code when opened.
(CVE-2007-4352, CVE-2007-5392, CVE-2007-5393)

A flaw was found in the t1lib library, used in the handling of Type 1
fonts. An attacker could create a malicious file that would cause
TeTeX to crash, or potentially execute arbitrary code when opened.
(CVE-2007-4033)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0711&L=scientific-linux-errata&T=0&P=2126
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6fe45b32"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/08");
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
if (rpm_check(release:"SL3", reference:"tetex-1.0.7-67.11")) flag++;
if (rpm_check(release:"SL3", reference:"tetex-afm-1.0.7-67.11")) flag++;
if (rpm_check(release:"SL3", reference:"tetex-doc-1.0.7-67.11")) flag++;
if (rpm_check(release:"SL3", reference:"tetex-dvips-1.0.7-67.11")) flag++;
if (rpm_check(release:"SL3", reference:"tetex-fonts-1.0.7-67.11")) flag++;
if (rpm_check(release:"SL3", reference:"tetex-latex-1.0.7-67.11")) flag++;
if (rpm_check(release:"SL3", reference:"tetex-xdvi-1.0.7-67.11")) flag++;

if (rpm_check(release:"SL4", reference:"tetex-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"SL4", reference:"tetex-afm-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"SL4", reference:"tetex-doc-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"SL4", reference:"tetex-dvips-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"SL4", reference:"tetex-fonts-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"SL4", reference:"tetex-latex-2.0.2-22.0.1.EL4.10")) flag++;
if (rpm_check(release:"SL4", reference:"tetex-xdvi-2.0.2-22.0.1.EL4.10")) flag++;

if (rpm_check(release:"SL5", reference:"tetex-3.0-33.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-afm-3.0-33.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-doc-3.0-33.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-dvips-3.0-33.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-fonts-3.0-33.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-latex-3.0-33.2.el5.2")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-xdvi-3.0-33.2.el5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

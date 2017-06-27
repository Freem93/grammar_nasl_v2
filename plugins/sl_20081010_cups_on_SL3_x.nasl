#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60483);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641");

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
"A buffer overflow flaw was discovered in the SGI image format decoding
routines used by the CUPS image converting filter 'imagetops'. An
attacker could create a malicious SGI image file that could, possibly,
execute arbitrary code as the 'lp' user if the file was printed.
(CVE-2008-3639)

An integer overflow flaw leading to a heap buffer overflow was
discovered in the Text-to-PostScript 'texttops' filter. An attacker
could create a malicious text file that could, possibly, execute
arbitrary code as the 'lp' user if the file was printed.
(CVE-2008-3640)

An insufficient buffer bounds checking flaw was discovered in the
HP-GL/2-to-PostScript 'hpgltops' filter. An attacker could create a
malicious HP-GL/2 file that could, possibly, execute arbitrary code as
the 'lp' user if the file was printed. (CVE-2008-3641)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0810&L=scientific-linux-errata&T=0&P=1204
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc769c0f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/10");
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
if (rpm_check(release:"SL3", reference:"cups-1.1.17-13.3.54")) flag++;
if (rpm_check(release:"SL3", reference:"cups-devel-1.1.17-13.3.54")) flag++;
if (rpm_check(release:"SL3", reference:"cups-libs-1.1.17-13.3.54")) flag++;

if (rpm_check(release:"SL4", reference:"cups-1.1.22-0.rc1.9.27.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"cups-devel-1.1.22-0.rc1.9.27.el4_7.1")) flag++;
if (rpm_check(release:"SL4", reference:"cups-libs-1.1.22-0.rc1.9.27.el4_7.1")) flag++;

if (rpm_check(release:"SL5", reference:"cups-1.2.4-11.18.el5_2.2")) flag++;
if (rpm_check(release:"SL5", reference:"cups-devel-1.2.4-11.18.el5_2.2")) flag++;
if (rpm_check(release:"SL5", reference:"cups-libs-1.2.4-11.18.el5_2.2")) flag++;
if (rpm_check(release:"SL5", reference:"cups-lpd-1.2.4-11.18.el5_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

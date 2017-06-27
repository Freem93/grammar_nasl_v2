#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60378);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2004-0888", "CVE-2008-0047", "CVE-2008-0053", "CVE-2008-1373", "CVE-2008-1374");

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
"SL5 Only: A heap buffer overflow flaw was found in a CUPS
administration interface CGI script. A local attacker able to connect
to the IPP port (TCP port 631) could send a malicious request causing
the script to crash or, potentially, execute arbitrary code as the
'lp' user. Please note: the default CUPS configuration in Red Hat
Enterprise Linux 5 does not allow remote connections to the IPP TCP
port. (CVE-2008-0047)

Two overflows were discovered in the HP-GL/2-to-PostScript filter. An
attacker could create a malicious HP-GL/2 file that could possibly
execute arbitrary code as the 'lp' user if the file is printed.
(CVE-2008-0053)

A buffer overflow flaw was discovered in the GIF decoding routines
used by CUPS image converting filters 'imagetops' and 'imagetoraster'.
An attacker could create a malicious GIF file that could possibly
execute arbitrary code as the 'lp' user if the file was printed.
(CVE-2008-1373)

SL 3 &amp; 4 Only: It was discovered that the patch used to address
CVE-2004-0888 in CUPS packages in Scientific Linux 3 and 4 did not
completely resolve the integer overflow in the 'pdftops' filter on
64-bit platforms. An attacker could create a malicious PDF file that
could possibly execute arbitrary code as the 'lp' user if the file was
printed. (CVE-2008-1374)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0804&L=scientific-linux-errata&T=0&P=76
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b76553d2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/01");
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
if (rpm_check(release:"SL3", reference:"cups-1.1.17-13.3.52")) flag++;
if (rpm_check(release:"SL3", reference:"cups-devel-1.1.17-13.3.52")) flag++;
if (rpm_check(release:"SL3", reference:"cups-libs-1.1.17-13.3.52")) flag++;

if (rpm_check(release:"SL4", reference:"cups-1.1.22-0.rc1.9.20.2.el4_6.6")) flag++;
if (rpm_check(release:"SL4", reference:"cups-devel-1.1.22-0.rc1.9.20.2.el4_6.6")) flag++;
if (rpm_check(release:"SL4", reference:"cups-libs-1.1.22-0.rc1.9.20.2.el4_6.6")) flag++;

if (rpm_check(release:"SL5", reference:"cups-1.2.4-11.14.el5_1.6")) flag++;
if (rpm_check(release:"SL5", reference:"cups-devel-1.2.4-11.14.el5_1.6")) flag++;
if (rpm_check(release:"SL5", reference:"cups-libs-1.2.4-11.14.el5_1.6")) flag++;
if (rpm_check(release:"SL5", reference:"cups-lpd-1.2.4-11.14.el5_1.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

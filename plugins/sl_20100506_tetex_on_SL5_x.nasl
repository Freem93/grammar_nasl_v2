#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60791);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0791", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-3608", "CVE-2009-3609", "CVE-2010-0739", "CVE-2010-0829", "CVE-2010-1440");

  script_name(english:"Scientific Linux Security Update : tetex on SL5.x i386/x86_64");
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
"Multiple integer overflow flaws were found in the way teTeX processed
special commands when converting DVI files into PostScript. An
attacker could create a malicious DVI file that would cause the dvips
executable to crash or, potentially, execute arbitrary code.
(CVE-2010-0739, CVE-2010-1440)

Multiple array index errors were found in the way teTeX converted DVI
files into the Portable Network Graphics (PNG) format. An attacker
could create a malicious DVI file that would cause the dvipng
executable to crash. (CVE-2010-0829)

teTeX embeds a copy of Xpdf, an open source Portable Document Format
(PDF) file viewer, to allow adding images in PDF format to the
generated PDF documents. The following issues affect Xpdf code :

Multiple integer overflow flaws were found in Xpdf's JBIG2 decoder. If
a local user generated a PDF file from a TeX document, referencing a
specially crafted PDF file, it would cause Xpdf to crash or,
potentially, execute arbitrary code with the privileges of the user
running pdflatex. (CVE-2009-0147, CVE-2009-1179)

Multiple integer overflow flaws were found in Xpdf. If a local user
generated a PDF file from a TeX document, referencing a specially
crafted PDF file, it would cause Xpdf to crash or, potentially,
execute arbitrary code with the privileges of the user running
pdflatex. (CVE-2009-0791, CVE-2009-3608, CVE-2009-3609) - Hide quoted
text -

A heap-based buffer overflow flaw was found in Xpdf's JBIG2 decoder.
If a local user generated a PDF file from a TeX document, referencing
a specially crafted PDF file, it would cause Xpdf to crash or,
potentially, execute arbitrary code with the privileges of the user
running pdflatex. (CVE-2009-0195)

Multiple buffer overflow flaws were found in Xpdf's JBIG2 decoder. If
a local user generated a PDF file from a TeX document, referencing a
specially crafted PDF file, it would cause Xpdf to crash or,
potentially, execute arbitrary code with the privileges of the user
running pdflatex. (CVE-2009-0146, CVE-2009-1182)

Multiple flaws were found in Xpdf's JBIG2 decoder that could lead to
the freeing of arbitrary memory. If a local user generated a PDF file
from a TeX document, referencing a specially crafted PDF file, it
would cause Xpdf to crash or, potentially, execute arbitrary code with
the privileges of the user running pdflatex. (CVE-2009-0166,
CVE-2009-1180)

Multiple input validation flaws were found in Xpdf's JBIG2 decoder. If
a local user generated a PDF file from a TeX document, referencing a
specially crafted PDF file, it would cause Xpdf to crash or,
potentially, execute arbitrary code with the privileges of the user
running pdflatex. (CVE-2009-0800)

Multiple denial of service flaws were found in Xpdf's JBIG2 decoder.
If a local user generated a PDF file from a TeX document, referencing
a specially crafted PDF file, it would cause Xpdf to crash.
(CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1005&L=scientific-linux-errata&T=0&P=711
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80cfbe2f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/06");
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
if (rpm_check(release:"SL5", reference:"tetex-3.0-33.8.el5_5.5")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-afm-3.0-33.8.el5_5.5")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-doc-3.0-33.8.el5_5.5")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-dvips-3.0-33.8.el5_5.5")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-fonts-3.0-33.8.el5_5.5")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-latex-3.0-33.8.el5_5.5")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-xdvi-3.0-33.8.el5_5.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

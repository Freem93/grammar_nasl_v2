#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61204);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/27 14:30:01 $");

  script_cve_id("CVE-2009-4274", "CVE-2011-4516");

  script_name(english:"Scientific Linux Security Update : netpbm on SL4.x, SL5.x i386/x86_64");
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
"The netpbm packages contain a library of functions which support
programs for handling various graphics file formats, including .pbm
(Portable Bit Map), .pgm (Portable Gray Map), .pnm (Portable Any Map),
.ppm (Portable Pixel Map), and others.

Two heap-based buffer overflow flaws were found in the embedded JasPer
library, which is used to provide support for Part 1 of the JPEG 2000
image compression standard in the jpeg2ktopam and pamtojpeg2k tools.
An attacker could create a malicious JPEG 2000 compressed image file
that could cause jpeg2ktopam to crash or, potentially, execute
arbitrary code with the privileges of the user running jpeg2ktopam.
These flaws do not affect pamtojpeg2k. (CVE-2011-4516, CVE-2011-4517)

A stack-based buffer overflow flaw was found in the way the xpmtoppm
tool processed X PixMap (XPM) image files. An attacker could create a
malicious XPM file that would cause xpmtoppm to crash or, potentially,
execute arbitrary code with the privileges of the user running
xpmtoppm. (CVE-2009-4274)

All users of netpbm are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=2752
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?442772ab"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/12");
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
if (rpm_check(release:"SL4", reference:"netpbm-10.35.58-8.el4")) flag++;
if (rpm_check(release:"SL4", reference:"netpbm-debuginfo-10.35.58-8.el4")) flag++;
if (rpm_check(release:"SL4", reference:"netpbm-devel-10.35.58-8.el4")) flag++;
if (rpm_check(release:"SL4", reference:"netpbm-progs-10.35.58-8.el4")) flag++;

if (rpm_check(release:"SL5", reference:"netpbm-10.35.58-8.el5_7.3")) flag++;
if (rpm_check(release:"SL5", reference:"netpbm-debuginfo-10.35.58-8.el5_7.3")) flag++;
if (rpm_check(release:"SL5", reference:"netpbm-devel-10.35.58-8.el5_7.3")) flag++;
if (rpm_check(release:"SL5", reference:"netpbm-progs-10.35.58-8.el5_7.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

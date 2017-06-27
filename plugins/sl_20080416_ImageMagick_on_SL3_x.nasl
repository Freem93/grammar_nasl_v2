#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60382);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4988", "CVE-2008-1096", "CVE-2008-1097");

  script_name(english:"Scientific Linux Security Update : ImageMagick on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"Several heap-based buffer overflow flaws were found in ImageMagick. If
a victim opened a specially crafted DCM or XWD file, an attacker could
potentially execute arbitrary code on the victim's machine.
(CVE-2007-1797)

Several denial of service flaws were found in ImageMagick's parsing of
XCF and DCM files. Attempting to process a specially crafted input
file in these formats could cause ImageMagick to enter an infinite
loop. (CVE-2007-4985)

Several integer overflow flaws were found in ImageMagick. If a victim
opened a specially crafted DCM, DIB, XBM, XCF or XWD file, an attacker
could potentially execute arbitrary code with the privileges of the
user running ImageMagick. (CVE-2007-4986)

An integer overflow flaw was found in ImageMagick's DIB parsing code.
If a victim opened a specially crafted DIB file, an attacker could
potentially execute arbitrary code with the privileges of the user
running ImageMagick. (CVE-2007-4988)

A heap-based buffer overflow flaw was found in the way ImageMagick
parsed XCF files. If a specially crafted XCF image was opened,
ImageMagick could be made to overwrite heap memory beyond the bounds
of its allocated memory. This could, potentially, allow an attacker to
execute arbitrary code on the machine running ImageMagick.
(CVE-2008-1096)

A heap-based buffer overflow flaw was found in ImageMagick's
processing of certain malformed PCX images. If a victim opened a
specially crafted PCX file, an attacker could possibly execute
arbitrary code on the victim's machine. (CVE-2008-1097)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0804&L=scientific-linux-errata&T=0&P=582
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca61e616"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/16");
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
if (rpm_check(release:"SL3", reference:"ImageMagick-5.5.6-28")) flag++;
if (rpm_check(release:"SL3", reference:"ImageMagick-c++-5.5.6-28")) flag++;
if (rpm_check(release:"SL3", reference:"ImageMagick-c++-devel-5.5.6-28")) flag++;
if (rpm_check(release:"SL3", reference:"ImageMagick-devel-5.5.6-28")) flag++;
if (rpm_check(release:"SL3", reference:"ImageMagick-perl-5.5.6-28")) flag++;

if (rpm_check(release:"SL4", reference:"ImageMagick-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"ImageMagick-c++-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"ImageMagick-c++-devel-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"ImageMagick-devel-6.0.7.1-17.el4_6.1")) flag++;
if (rpm_check(release:"SL4", reference:"ImageMagick-perl-6.0.7.1-17.el4_6.1")) flag++;

if (rpm_check(release:"SL5", reference:"ImageMagick-6.2.8.0-4.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"ImageMagick-c++-6.2.8.0-4.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"ImageMagick-c++-devel-6.2.8.0-4.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"ImageMagick-devel-6.2.8.0-4.el5_1.1")) flag++;
if (rpm_check(release:"SL5", reference:"ImageMagick-perl-6.2.8.0-4.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60471);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2006-2193", "CVE-2008-2327");

  script_name(english:"Scientific Linux Security Update : libtiff on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"Multiple uses of uninitialized values were discovered in libtiff's
Lempel-Ziv-Welch (LZW) compression algorithm decoder. An attacker
could create a carefully crafted LZW-encoded TIFF file that would
cause an application linked with libtiff to crash or, possibly,
execute arbitrary code. (CVE-2008-2327)

SL4: A buffer overflow flaw was discovered in the tiff2pdf conversion
program distributed with libtiff. An attacker could create a TIFF file
containing UTF-8 characters that would, when converted to PDF format,
cause tiff2pdf to crash, or, possibly, execute arbitrary code.
(CVE-2006-2193)

SL4 &amp; SL5: Additionally, these updated packages fix the following
bug :

  - the libtiff packages included manual pages for the
    sgi2tiff and tiffsv commands, which are not included in
    these packages. These extraneous manual pages were
    removed."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0808&L=scientific-linux-errata&T=0&P=2181
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78b1fe59"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff and / or libtiff-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/28");
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
if (rpm_check(release:"SL3", reference:"libtiff-3.5.7-31.el3")) flag++;
if (rpm_check(release:"SL3", reference:"libtiff-devel-3.5.7-31.el3")) flag++;

if (rpm_check(release:"SL4", reference:"libtiff-3.6.1-12.el4_7.2")) flag++;
if (rpm_check(release:"SL4", reference:"libtiff-devel-3.6.1-12.el4_7.2")) flag++;

if (rpm_check(release:"SL5", reference:"libtiff-3.8.2-7.el5_2.2")) flag++;
if (rpm_check(release:"SL5", reference:"libtiff-devel-3.8.2-7.el5_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

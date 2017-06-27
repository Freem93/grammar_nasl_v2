#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60623);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-2285", "CVE-2009-2347");

  script_name(english:"Scientific Linux Security Update : libtiff for SL3.0.x, SL 4.x, SL 5.x on i386/x86_64");
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
"CVE-2009-2285 libtiff: LZWDecodeCompat underflow

CVE-2009-2347 libtiff: integer overflows in various inter-color spaces
conversion tools (crash, ACE)

Several integer overflow flaws, leading to heap-based buffer
overflows, were found in various libtiff color space conversion tools.
An attacker could create a specially crafted TIFF file, which once
opened by an unsuspecting user, would cause the conversion tool to
crash or, potentially, execute arbitrary code with the privileges of
the user running the tool. (CVE-2009-2347)

A buffer underwrite flaw was found in libtiff's Lempel-Ziv-Welch (LZW)
compression algorithm decoder. An attacker could create a specially
crafted LZW-encoded TIFF file, which once opened by an unsuspecting
user, would cause an application linked with libtiff to access an
out-of-bounds memory location, leading to a denial of service
(application crash). (CVE-2009-2285)

The CVE-2009-2347 flaws were discovered by Tielei Wang from
ICST-ERCIS, Peking University."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0907&L=scientific-linux-errata&T=0&P=2537
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?818fff76"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff and / or libtiff-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

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
if (rpm_check(release:"SL3", reference:"libtiff-3.5.7-33.el3")) flag++;
if (rpm_check(release:"SL3", reference:"libtiff-devel-3.5.7-33.el3")) flag++;

if (rpm_check(release:"SL4", reference:"libtiff-3.6.1-12.el4_8.4")) flag++;
if (rpm_check(release:"SL4", reference:"libtiff-devel-3.6.1-12.el4_8.4")) flag++;

if (rpm_check(release:"SL5", reference:"libtiff-3.8.2-7.el5_3.4")) flag++;
if (rpm_check(release:"SL5", reference:"libtiff-devel-3.8.2-7.el5_3.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

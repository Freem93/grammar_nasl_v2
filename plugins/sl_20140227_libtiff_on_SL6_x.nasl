#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(72739);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/28 11:48:21 $");

  script_cve_id("CVE-2010-2596", "CVE-2013-1960", "CVE-2013-1961", "CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");

  script_name(english:"Scientific Linux Security Update : libtiff on SL6.x i386/x86_64");
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
"A heap-based buffer overflow and a use-after-free flaw were found in
the tiff2pdf tool. An attacker could use these flaws to create a
specially crafted TIFF file that would cause tiff2pdf to crash or,
possibly, execute arbitrary code. (CVE-2013-1960, CVE-2013-4232)

Multiple buffer overflow flaws were found in the gif2tiff tool. An
attacker could use these flaws to create a specially crafted GIF file
that could cause gif2tiff to crash or, possibly, execute arbitrary
code. (CVE-2013-4231, CVE-2013-4243, CVE-2013-4244)

A flaw was found in the way libtiff handled OJPEG-encoded TIFF images.
An attacker could use this flaw to create a specially crafted TIFF
file that would cause an application using libtiff to crash.
(CVE-2010-2596)

Multiple buffer overflow flaws were found in the tiff2pdf tool. An
attacker could use these flaws to create a specially crafted TIFF file
that would cause tiff2pdf to crash. (CVE-2013-1961)

All running applications linked against libtiff must be restarted for
this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1402&L=scientific-linux-errata&T=0&P=3091
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b0af6bf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"libtiff-3.9.4-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-debuginfo-3.9.4-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-devel-3.9.4-10.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-static-3.9.4-10.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

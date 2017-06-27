#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(63314);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-3401", "CVE-2012-4447", "CVE-2012-4564", "CVE-2012-5581");

  script_name(english:"Scientific Linux Security Update : libtiff on SL5.x, SL6.x i386/x86_64");
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
"A heap-based buffer overflow flaw was found in the way libtiff
processed certain TIFF images using the Pixar Log Format encoding. An
attacker could create a specially crafted TIFF file that, when opened,
could cause an application using libtiff to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2012-4447)

A stack-based buffer overflow flaw was found in the way libtiff
handled DOTRANGE tags. An attacker could use this flaw to create a
specially crafted TIFF file that, when opened, would cause an
application linked against libtiff to crash or, possibly, execute
arbitrary code. (CVE-2012-5581)

A heap-based buffer overflow flaw was found in the tiff2pdf tool. An
attacker could use this flaw to create a specially crafted TIFF file
that would cause tiff2pdf to crash or, possibly, execute arbitrary
code. (CVE-2012-3401)

A missing return value check flaw, leading to a heap-based buffer
overflow, was found in the ppm2tiff tool. An attacker could use this
flaw to create a specially crafted PPM (Portable Pixel Map) file that
would cause ppm2tiff to crash or, possibly, execute arbitrary code.
(CVE-2012-4564)

All running applications linked against libtiff must be restarted for
this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1212&L=scientific-linux-errata&T=0&P=1304
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37b448a5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"libtiff-3.8.2-18.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"libtiff-debuginfo-3.8.2-18.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"libtiff-devel-3.8.2-18.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"libtiff-3.9.4-9.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-debuginfo-3.9.4-9.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-devel-3.9.4-9.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libtiff-static-3.9.4-9.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

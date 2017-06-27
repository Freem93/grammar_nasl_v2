#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61255);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2010-4167");

  script_name(english:"Scientific Linux Security Update : ImageMagick on SL5.x i386/x86_64");
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
"ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

It was found that ImageMagick utilities tried to load ImageMagick
configuration files from the current working directory. If a user ran
an ImageMagick utility in an attacker-controlled directory containing
a specially crafted ImageMagick configuration file, it could cause the
utility to execute arbitrary code. (CVE-2010-4167)

This update also fixes the following bugs :

  - Previously, the 'identify -verbose' command failed with
    an assertion if there was no image information
    available. An upstream patch has been applied, so that
    GetImageOption() is now called correctly. Now, the
    'identify -verbose' command works correctly even if no
    image information is available.

  - Previously, an incorrect use of the semaphore data type
    led to a deadlock. As a consequence, the ImageMagick
    utility could become unresponsive when converting JPEG
    files to PDF (Portable Document Format) files. A patch
    has been applied to address the deadlock issue, and JPEG
    files can now be properly converted to PDF files.

  - Previously, running the 'convert' command with the
    '-color' option failed with a memory allocation error.
    The source code has been modified to fix problems with
    memory allocation. Now, using the 'convert' command with
    the '-color' option works correctly.

  - Previously, ImageMagick could become unresponsive when
    using the 'display' command on damaged GIF files. The
    source code has been revised to prevent the issue.
    ImageMagick now produces an error message in the
    described scenario. A file selector is now opened so the
    user can choose another image to display.

  - Prior to this update, the 'convert' command did not
    handle rotated PDF files correctly. As a consequence,
    the output was rendered as a portrait with the content
    being cropped. With this update, the PDF render geometry
    is modified, and the output produced by the 'convert'
    command is properly rendered as a landscape.

All users of ImageMagick are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of ImageMagick must be restarted for this update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=2400
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?312ecbd9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL5", reference:"ImageMagick-6.2.8.0-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"ImageMagick-c++-6.2.8.0-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"ImageMagick-c++-devel-6.2.8.0-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"ImageMagick-debuginfo-6.2.8.0-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"ImageMagick-devel-6.2.8.0-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"ImageMagick-perl-6.2.8.0-12.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

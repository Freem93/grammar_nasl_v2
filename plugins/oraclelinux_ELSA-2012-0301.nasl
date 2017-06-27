#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0301 and 
# Oracle Linux Security Advisory ELSA-2012-0301 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68472);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2010-4167");
  script_bugtraq_id(25763, 28821, 28822, 35111, 45044);
  script_osvdb_id(69445);
  script_xref(name:"RHSA", value:"2012:0301");

  script_name(english:"Oracle Linux 5 : ImageMagick (ELSA-2012-0301)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0301 :

Updated ImageMagick packages that fix one security issue and multiple
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

It was found that ImageMagick utilities tried to load ImageMagick
configuration files from the current working directory. If a user ran
an ImageMagick utility in an attacker-controlled directory containing
a specially crafted ImageMagick configuration file, it could cause the
utility to execute arbitrary code. (CVE-2010-4167)

This update also fixes the following bugs :

* Previously, the 'identify -verbose' command failed with an assertion
if there was no image information available. An upstream patch has
been applied, so that GetImageOption() is now called correctly. Now,
the 'identify -verbose' command works correctly even if no image
information is available. (BZ#502626)

* Previously, an incorrect use of the semaphore data type led to a
deadlock. As a consequence, the ImageMagick utility could become
unresponsive when converting JPEG files to PDF (Portable Document
Format) files. A patch has been applied to address the deadlock issue,
and JPEG files can now be properly converted to PDF files. (BZ#530592)

* Previously, running the 'convert' command with the '-color' option
failed with a memory allocation error. The source code has been
modified to fix problems with memory allocation. Now, using the
'convert' command with the '-color' option works correctly.
(BZ#616538)

* Previously, ImageMagick could become unresponsive when using the
'display' command on damaged GIF files. The source code has been
revised to prevent the issue. ImageMagick now produces an error
message in the described scenario. A file selector is now opened so
the user can choose another image to display. (BZ#693989)

* Prior to this update, the 'convert' command did not handle rotated
PDF files correctly. As a consequence, the output was rendered as a
portrait with the content being cropped. With this update, the PDF
render geometry is modified, and the output produced by the 'convert'
command is properly rendered as a landscape. (BZ#694922)

All users of ImageMagick are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of ImageMagick must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002652.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"ImageMagick-6.2.8.0-12.el5")) flag++;
if (rpm_check(release:"EL5", reference:"ImageMagick-c++-6.2.8.0-12.el5")) flag++;
if (rpm_check(release:"EL5", reference:"ImageMagick-c++-devel-6.2.8.0-12.el5")) flag++;
if (rpm_check(release:"EL5", reference:"ImageMagick-devel-6.2.8.0-12.el5")) flag++;
if (rpm_check(release:"EL5", reference:"ImageMagick-perl-6.2.8.0-12.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}

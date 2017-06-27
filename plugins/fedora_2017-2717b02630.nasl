#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-2717b02630.
#

include("compat.inc");

if (description)
{
  script_id(96706);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/31 14:53:42 $");

  script_cve_id("CVE-2016-6912", "CVE-2016-9317");
  script_xref(name:"FEDORA", value:"2017-2717b02630");

  script_name(english:"Fedora 24 : gd (2017-2717b02630)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## Version 2.2.4 - 2017-01-18

### Security

  - gdImageCreate() doesn't check for oversized images and
    as such is prone to DoS vulnerabilities. (CVE-2016-9317)

  - double-free in gdImageWebPtr() (CVE-2016-6912)

  - potential unsigned underflow in gd_interpolation.c

  - DOS vulnerability in gdImageCreateFromGd2Ctx()

### Fixed

  - Fix #354: Signed Integer Overflow gd_io.c

  - Fix #340: System frozen

  - Fix OOB reads of the TGA decompression buffer

  - Fix DOS vulnerability in gdImageCreateFromGd2Ctx()

  - Fix potential unsigned underflow

  - Fix double-free in gdImageWebPtr()

  - Fix invalid read in gdImageCreateFromTiffPtr()

  - Fix OOB reads of the TGA decompression buffer

  - Fix #68: gif: buffer underflow reported by
    AddressSanitizer

  - Avoid potentially dangerous signed to unsigned
    conversion

  - Fix #304: test suite failure in gif/bug00006 [2.2.3]

  - Fix #329: GD_BILINEAR_FIXED gdImageScale() can cause
    black border

  - Fix #330: Integer overflow in
    gdImageScaleBilinearPalette()

  - Fix 321: NULL pointer dereferences in
    gdImageRotateInterpolated

  - Fix whitespace and add missing comment block

  - Fix #319: gdImageRotateInterpolated can have wrong
    background color

  - Fix color quantization documentation

  - Fix #309: gdImageGd2() writes wrong chunk sizes on
    boundaries

  - Fix #307: GD_QUANT_NEUQUANT fails to unset trueColor
    flag

  - Fix #300: gdImageClone() assigns res_y = res_x

  - Fix #299: Regression regarding gdImageRectangle() with
    gdImageSetThickness()

  - Replace GNU old-style field designators with C89
    compatible initializers

  - Fix #297: gdImageCrop() converts palette image to
    truecolor image

  - Fix #290: TGA RLE decoding is broken

  - Fix unnecessary non NULL checks

  - Fix #289: Passing unrecognized formats to gdImageGd2
    results in corrupted files

  - Fix #280: gdImageWebpEx() `quantization` parameter is a
    misnomer

  - Publish all gdImageCreateFromWebp*() functions and
    gdImageWebpCtx()

  - Fix issue #276: Sometimes pixels are missing when
    storing images as BMPs

  - Fix issue #275: gdImageBmpCtx() may segfault for
    non-seekable contexts

  - Fix copy&paste error in gdImageScaleBicubicFixed()

### Added

  - More documentation

  - Documentation on GD and GD2 formats

  - More tests

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-2717b02630"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gd package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"gd-2.2.4-1.fc24")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gd");
}

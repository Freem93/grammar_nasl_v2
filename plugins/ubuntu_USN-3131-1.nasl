#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3131-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95053);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/21 20:33:29 $");

  script_cve_id("CVE-2014-8354", "CVE-2014-8355", "CVE-2014-8562", "CVE-2014-8716", "CVE-2014-9805", "CVE-2014-9806", "CVE-2014-9807", "CVE-2014-9808", "CVE-2014-9809", "CVE-2014-9810", "CVE-2014-9811", "CVE-2014-9812", "CVE-2014-9813", "CVE-2014-9814", "CVE-2014-9815", "CVE-2014-9816", "CVE-2014-9817", "CVE-2014-9818", "CVE-2014-9819", "CVE-2014-9820", "CVE-2014-9821", "CVE-2014-9822", "CVE-2014-9823", "CVE-2014-9826", "CVE-2014-9828", "CVE-2014-9829", "CVE-2014-9830", "CVE-2014-9831", "CVE-2014-9833", "CVE-2014-9834", "CVE-2014-9835", "CVE-2014-9836", "CVE-2014-9837", "CVE-2014-9838", "CVE-2014-9839", "CVE-2014-9840", "CVE-2014-9841", "CVE-2014-9843", "CVE-2014-9844", "CVE-2014-9845", "CVE-2014-9846", "CVE-2014-9847", "CVE-2014-9848", "CVE-2014-9849", "CVE-2014-9850", "CVE-2014-9851", "CVE-2014-9853", "CVE-2014-9854", "CVE-2014-9907", "CVE-2015-8894", "CVE-2015-8895", "CVE-2015-8896", "CVE-2015-8897", "CVE-2015-8898", "CVE-2015-8900", "CVE-2015-8901", "CVE-2015-8902", "CVE-2015-8903", "CVE-2015-8957", "CVE-2015-8958", "CVE-2015-8959", "CVE-2016-4562", "CVE-2016-4563", "CVE-2016-4564", "CVE-2016-5010", "CVE-2016-5687", "CVE-2016-5688", "CVE-2016-5689", "CVE-2016-5690", "CVE-2016-5691", "CVE-2016-5841", "CVE-2016-5842", "CVE-2016-6491", "CVE-2016-6823", "CVE-2016-7101", "CVE-2016-7513", "CVE-2016-7514", "CVE-2016-7515", "CVE-2016-7516", "CVE-2016-7517", "CVE-2016-7518", "CVE-2016-7519", "CVE-2016-7520", "CVE-2016-7521", "CVE-2016-7522", "CVE-2016-7523", "CVE-2016-7524", "CVE-2016-7525", "CVE-2016-7526", "CVE-2016-7527", "CVE-2016-7528", "CVE-2016-7529", "CVE-2016-7530", "CVE-2016-7531", "CVE-2016-7532", "CVE-2016-7533", "CVE-2016-7534", "CVE-2016-7535", "CVE-2016-7536", "CVE-2016-7537", "CVE-2016-7538", "CVE-2016-7539", "CVE-2016-7540");
  script_osvdb_id(113923, 113932, 113933, 114425, 116360, 116361, 116362, 116363, 116367, 116369, 116370, 116372, 116373, 116374, 116377, 116378, 116380, 116383, 116384, 116385, 116386, 116387, 116389, 116390, 116391, 116393, 116394, 116395, 116396, 116397, 116398, 116399, 116400, 116401, 116402, 116403, 116404, 116405, 116407, 116408, 116409, 116410, 116411, 116412, 116413, 116414, 116416, 116417, 116418, 116419, 116915, 116919, 118660, 118661, 118662, 118663, 127960, 128603, 128604, 129831, 134466, 134467, 134469, 134470, 134471, 134473, 134474, 134475, 134476, 134478, 134480, 134481, 134482, 134484, 134485, 134486, 134489, 134490, 134492, 134635, 135625, 135813, 138399, 139335, 139336, 139337, 140067, 140068, 140069, 140070, 140071, 140072, 140442, 140613, 142216, 142322, 142338, 142568, 142846, 142859, 142860, 142880, 142923, 142933, 143042, 143617);
  script_xref(name:"USN", value:"3131-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS / 16.10 : imagemagick vulnerabilities (USN-3131-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that ImageMagick incorrectly handled certain
malformed image files. If a user or automated system using ImageMagick
were tricked into opening a specially crafted image, an attacker could
exploit this to cause a denial of service or possibly execute code
with the privileges of the user invoking the program.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++-6.q16-5v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagick++5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore-6.q16-2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore4-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmagickcore5-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(12\.04|14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"imagemagick", pkgver:"8:6.6.9.7-5ubuntu3.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagick++4", pkgver:"8:6.6.9.7-5ubuntu3.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagickcore4", pkgver:"8:6.6.9.7-5ubuntu3.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"libmagickcore4-extra", pkgver:"8:6.6.9.7-5ubuntu3.5")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"imagemagick", pkgver:"8:6.7.7.10-6ubuntu3.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagick++5", pkgver:"8:6.7.7.10-6ubuntu3.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagickcore5", pkgver:"8:6.7.7.10-6ubuntu3.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmagickcore5-extra", pkgver:"8:6.7.7.10-6ubuntu3.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick", pkgver:"8:6.8.9.9-7ubuntu5.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"imagemagick-6.q16", pkgver:"8:6.8.9.9-7ubuntu5.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagick++-6.q16-5v5", pkgver:"8:6.8.9.9-7ubuntu5.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2", pkgver:"8:6.8.9.9-7ubuntu5.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libmagickcore-6.q16-2-extra", pkgver:"8:6.8.9.9-7ubuntu5.2")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"imagemagick", pkgver:"8:6.8.9.9-7ubuntu8.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"imagemagick-6.q16", pkgver:"8:6.8.9.9-7ubuntu8.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libmagick++-6.q16-5v5", pkgver:"8:6.8.9.9-7ubuntu8.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libmagickcore-6.q16-2", pkgver:"8:6.8.9.9-7ubuntu8.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libmagickcore-6.q16-2-extra", pkgver:"8:6.8.9.9-7ubuntu8.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "imagemagick / imagemagick-6.q16 / libmagick++-6.q16-5v5 / etc");
}

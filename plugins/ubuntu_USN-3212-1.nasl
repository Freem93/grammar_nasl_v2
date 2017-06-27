#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3212-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97434);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/02 14:41:04 $");

  script_cve_id("CVE-2015-7554", "CVE-2015-8668", "CVE-2016-10092", "CVE-2016-10093", "CVE-2016-10094", "CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3624", "CVE-2016-3632", "CVE-2016-3658", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-5314", "CVE-2016-5315", "CVE-2016-5316", "CVE-2016-5317", "CVE-2016-5320", "CVE-2016-5321", "CVE-2016-5322", "CVE-2016-5323", "CVE-2016-5652", "CVE-2016-5875", "CVE-2016-6223", "CVE-2016-8331", "CVE-2016-9273", "CVE-2016-9297", "CVE-2016-9448", "CVE-2016-9453", "CVE-2016-9532", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9538", "CVE-2016-9539", "CVE-2016-9540", "CVE-2017-5225");
  script_osvdb_id(117750, 132278, 132279, 136741, 136836, 136837, 136838, 136839, 137083, 137084, 140006, 140007, 140008, 140009, 140016, 140117, 140118, 141537, 141540, 145021, 145022, 145023, 145728, 145751, 145752, 145753, 146185, 146273, 147159, 147303, 147314, 147758, 147779, 148165, 148170, 149138, 149991);
  script_xref(name:"USN", value:"3212-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 16.10 : tiff vulnerabilities (USN-3212-1)");
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
"It was discovered that LibTIFF incorrectly handled certain malformed
images. If a user or automated system were tricked into opening a
specially crafted image, a remote attacker could crash the
application, leading to a denial of service, or possibly execute
arbitrary code with user privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff-tools and / or libtiff5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:U");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017 Canonical, Inc. / NASL script (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|16\.04|16\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 16.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"libtiff-tools", pkgver:"4.0.3-7ubuntu0.6")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libtiff5", pkgver:"4.0.3-7ubuntu0.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libtiff-tools", pkgver:"4.0.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libtiff5", pkgver:"4.0.6-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libtiff-tools", pkgver:"4.0.6-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"16.10", pkgname:"libtiff5", pkgver:"4.0.6-2ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff-tools / libtiff5");
}

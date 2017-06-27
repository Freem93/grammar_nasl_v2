#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2747-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86189);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/24 17:44:50 $");

  script_cve_id("CVE-2015-5950");
  script_osvdb_id(128139);
  script_xref(name:"USN", value:"2747-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 15.04 : nvidia-graphics-drivers-304, nvidia-graphics-drivers-304-updates, nvidia-graphics-drivers-340, nvidia-graphics-drivers-340-updates, nvidia-graphics-drivers-346, nvidia-graphics-drivers-346-updates, jockey vulnerability (USN-2747-1)");
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
"Dario Weisser discovered that the NVIDIA graphics drivers incorrectly
handled certain IOCTL writes. A local attacker could use this issue to
possibly gain root privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:jockey-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-304");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-304-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-340");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-340-updates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-346");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-346-updates");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|15\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 15.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"jockey-common", pkgver:"0.9.7-0ubuntu7.16")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"nvidia-304", pkgver:"304.128-0ubuntu0.0.0.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"nvidia-304-updates", pkgver:"304.128-0ubuntu0.0.0.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"nvidia-340", pkgver:"340.93-0ubuntu0.0.0.1")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"nvidia-340-updates", pkgver:"340.93-0ubuntu0.0.0.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-304", pkgver:"304.128-0ubuntu0.0.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-304-updates", pkgver:"304.128-0ubuntu0.0.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-340", pkgver:"340.93-0ubuntu0.0.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-340-updates", pkgver:"340.93-0ubuntu0.0.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-346", pkgver:"346.96-0ubuntu0.0.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"nvidia-346-updates", pkgver:"346.96-0ubuntu0.0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-304", pkgver:"304.128-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-304-updates", pkgver:"304.128-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-340", pkgver:"340.93-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-340-updates", pkgver:"340.93-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-346", pkgver:"346.96-0ubuntu0.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"nvidia-346-updates", pkgver:"346.96-0ubuntu0.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jockey-common / nvidia-304 / nvidia-304-updates / nvidia-340 / etc");
}

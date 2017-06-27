#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2908-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88897);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/26 14:26:00 $");

  script_cve_id("CVE-2013-4312", "CVE-2015-8785", "CVE-2016-1575", "CVE-2016-1576", "CVE-2016-2069");
  script_xref(name:"USN", value:"2908-1");

  script_name(english:"Ubuntu 15.10 : linux vulnerabilities (USN-2908-1)");
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
"halfdog discovered that OverlayFS, when mounting on top of a FUSE
mount, incorrectly propagated file attributes, including setuid. A
local unprivileged attacker could use this to gain privileges.
(CVE-2016-1576)

halfdog discovered that OverlayFS in the Linux kernel incorrectly
propagated security sensitive extended attributes, such as POSIX ACLs.
A local unprivileged attacker could use this to gain privileges.
(CVE-2016-1575)

It was discovered that the Linux kernel did not properly enforce
rlimits for file descriptors sent over UNIX domain sockets. A local
attacker could use this to cause a denial of service. (CVE-2013-4312)

It was discovered that the Linux kernel's Filesystem in Userspace
(FUSE) implementation did not handle initial zero length segments
properly. A local attacker could use this to cause a denial of service
(unkillable task). (CVE-2015-8785)

Andy Lutomirski discovered a race condition in the Linux kernel's
translation lookaside buffer (TLB) handling of flush events. A local
attacker could use this to cause a denial of service or possibly leak
sensitive information. (CVE-2016-2069).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected linux-image-4.2-generic,
linux-image-4.2-generic-lpae and / or linux-image-4.2-lowlatency
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/23");
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
if (! ereg(pattern:"^(15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"15.10", pkgname:"linux-image-4.2.0-30-generic", pkgver:"4.2.0-30.35")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"linux-image-4.2.0-30-generic-lpae", pkgver:"4.2.0-30.35")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"linux-image-4.2.0-30-lowlatency", pkgver:"4.2.0-30.35")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.2-generic / linux-image-4.2-generic-lpae / etc");
}

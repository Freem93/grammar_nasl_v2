#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-509-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28113);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/01 21:07:51 $");

  script_cve_id("CVE-2007-3104", "CVE-2007-3105", "CVE-2007-3513", "CVE-2007-3848", "CVE-2007-3851", "CVE-2007-4308");
  script_osvdb_id(37115, 37116, 37122, 37124, 37288, 37289);
  script_xref(name:"USN", value:"509-1");

  script_name(english:"Ubuntu 6.10 : linux-source-2.6.17 vulnerabilities (USN-509-1)");
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
"A flaw in the sysfs_readdir function allowed a local user to cause a
denial of service by dereferencing a NULL pointer. (CVE-2007-3104)

A buffer overflow was discovered in the random number generator. In
environments with granular assignment of root privileges, a local
attacker could gain additional privileges. (CVE-2007-3105)

A flaw was discovered in the usblcd driver. A local attacker could
cause large amounts of kernel memory consumption, leading to a denial
of service. (CVE-2007-3513)

It was discovered that certain setuid-root processes did not correctly
reset process death signal handlers. A local user could manipulate
this to send signals to processes they would not normally have access
to. (CVE-2007-3848)

The Direct Rendering Manager for the i915 driver could be made to
write to arbitrary memory locations. An attacker with access to a
running X11 session could send a specially crafted buffer and gain
root privileges. (CVE-2007-3851)

It was discovered that the aacraid SCSI driver did not correctly check
permissions on certain ioctls. A local attacker could cause a denial
of service or gain privileges. (CVE-2007-4308).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.17");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.10", pkgname:"linux-doc-2.6.17", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-386", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-generic", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-headers-2.6.17-12-server", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-386", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-generic", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-2.6.17-12-server", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-386", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-generic", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-debug-2.6.17-12-server", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-image-kdump", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-kernel-devel", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-libc-dev", pkgver:"2.6.17.1-12.40")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"linux-source-2.6.17", pkgver:"2.6.17.1-12.40")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.17 / linux-headers-2.6 / linux-headers-2.6-386 / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1696-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64432);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/26 14:05:58 $");

  script_cve_id("CVE-2012-4461", "CVE-2012-4530", "CVE-2012-5532");
  script_xref(name:"USN", value:"1696-2");

  script_name(english:"Ubuntu 12.04 LTS : linux regression (USN-1696-2)");
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
"USN-1696-1 fixed vulnerabilities in the Linux kernel. Due to an
unrelated regression inotify/fanotify stopped working after upgrading.
This update fixes the problem.

We apologize for the inconvenience.

Jon Howell reported a flaw in the Linux kernel's KVM (Kernel-based
virtual machine) subsystem's handling of the XSAVE feature. On hosts,
using qemu userspace, without the XSAVE feature an unprivileged local
attacker could exploit this flaw to crash the system. (CVE-2012-4461)

A flaw was discovered in the Linux kernel's handling of
script execution when module loading is enabled. A local
attacker could exploit this flaw to cause a leak of kernel
stack contents. (CVE-2012-4530)

Florian Weimer discovered that hypervkvpd, which is
distributed in the Linux kernel, was not correctly
validating source addresses of netlink packets. An untrusted
local user can cause a denial of service by causing
hypervkvpd to exit. (CVE-2012-5532).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2016 Canonical, Inc. / NASL script (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-37-generic", pkgver:"3.2.0-37.58")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-37-generic-pae", pkgver:"3.2.0-37.58")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-37-highbank", pkgver:"3.2.0-37.58")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-37-virtual", pkgver:"3.2.0-37.58")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.2-generic / linux-image-3.2-generic-pae / etc");
}

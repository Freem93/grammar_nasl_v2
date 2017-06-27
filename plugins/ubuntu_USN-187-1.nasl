#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-187-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20599);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/26 14:05:59 $");

  script_cve_id("CVE-2005-1767", "CVE-2005-3044");
  script_osvdb_id(18702, 19597, 19598);
  script_xref(name:"USN", value:"187-1");

  script_name(english:"Ubuntu 4.10 / 5.04 : linux-source-2.6.10, linux-source-2.6.8.1 vulnerabilities (USN-187-1)");
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
"A Denial of Service vulnerability was detected in the stack segment
fault handler. A local attacker could exploit this by causing stack
fault exceptions under special circumstances (scheduling), which lead
to a kernel crash. (CAN-2005-1767)

Vasiliy Averin discovered a Denial of Service vulnerability in the
'tiocgdev' ioctl call and in the 'routing_ioctl' function. By calling
fget() and fput() in special ways, a local attacker could exploit this
to destroy file descriptor structures and crash the kernel.
(CAN-2005-3044).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6.8.1-5-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-686-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-k8-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6.8.1-5-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-debian-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-patch-ubuntu-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tree-2.6.8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"linux-doc-2.6.8.1", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-386", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-686", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-686-smp", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-generic", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-k8", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-k8-smp", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-headers-2.6.8.1-5-amd64-xeon", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-386", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-686", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-686-smp", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-generic", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-k8", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-k8-smp", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-image-2.6.8.1-5-amd64-xeon", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-patch-debian-2.6.8.1", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-source-2.6.8.1", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"linux-tree-2.6.8.1", pkgver:"2.6.8.1-16.23")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-doc-2.6.10", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-386", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-686", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-686-smp", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-generic", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-k8", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-k8-smp", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-headers-2.6.10-5-amd64-xeon", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-386", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-686", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-686-smp", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-generic", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-k8", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-k8-smp", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-image-2.6.10-5-amd64-xeon", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-patch-ubuntu-2.6.10", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-source-2.6.10", pkgver:"2.6.10-34.6")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"linux-tree-2.6.10", pkgver:"2.6.10-34.6")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.10 / linux-doc-2.6.8.1 / linux-headers-2.6 / etc");
}
